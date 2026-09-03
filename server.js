require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || `http://localhost:${PORT}`;
const FEE_RATE = 0.03;

const applications = new Map();
const payments = new Map();

const allowedOrigins = (process.env.FRONTEND_ORIGIN || '').split(',').map(v => v.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Origin not allowed by CORS'));
  }
}));

// Paystack webhook must receive the raw request body for signature verification.
app.post('/paystack/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  if (!PAYSTACK_SECRET_KEY) return res.sendStatus(503);

  const signature = req.headers['x-paystack-signature'];
  const expected = crypto
    .createHmac('sha512', PAYSTACK_SECRET_KEY)
    .update(req.body)
    .digest('hex');

  if (!signature) return res.sendStatus(401);
  const provided = Buffer.from(String(signature), 'utf8');
  const expectedBuffer = Buffer.from(expected, 'utf8');
  if (provided.length !== expectedBuffer.length || !crypto.timingSafeEqual(provided, expectedBuffer)) {
    return res.sendStatus(401);
  }

  try {
    const event = JSON.parse(req.body.toString('utf8'));
    if (event.event === 'charge.success') {
      const reference = event.data?.reference;
      const payment = payments.get(reference);
      if (payment) {
        const paidAmount = Number(event.data?.amount || 0);
        if (paidAmount === payment.amountSubunit) {
          payment.status = 'success';
          payment.updatedAt = new Date().toISOString();
          const application = applications.get(payment.applicationReference);
          if (application) application.status = 'payment_success';
        }
      }
    }
  } catch (_) {
    return res.sendStatus(400);
  }

  res.sendStatus(200);
});

app.use(express.json({ limit: '100kb' }));

function normalisePhone(phone) {
  const value = String(phone || '').replace(/[\s-]/g, '');
  if (/^\+2547\d{8}$/.test(value)) return value;
  if (/^2547\d{8}$/.test(value)) return `+${value}`;
  if (/^07\d{8}$/.test(value)) return `+254${value.slice(1)}`;
  return null;
}

function validIdentity(identity) {
  return identity &&
    typeof identity.firstName === 'string' && identity.firstName.trim() &&
    typeof identity.lastName === 'string' && identity.lastName.trim() &&
    normalisePhone(identity.phone) &&
    identity.country === 'Kenya' &&
    typeof identity.town === 'string' && identity.town.trim();
}

function limitsFor() {
  return { min: 5000, max: 80000 };
}

function calculateFee(amount) {
  return Math.round(Number(amount) * FEE_RATE);
}

function createReference(prefix = 'PWL') {
  return `${prefix}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'Pawa Loans API' });
});

app.post('/api/eligibility', (req, res) => {
  const { service = 'Pawa Loans', identity } = req.body || {};
  const limits = limitsFor();

  if (!validIdentity(identity)) {
    return res.status(400).json({ success: false, message: 'Complete and valid identity information is required.' });
  }

  // This endpoint exposes the portal's configured application ceiling. It is not a
  // credit-bureau decision or a guaranteed loan approval. Final eligibility must be
  // determined by the authorized lender using its actual underwriting rules.
  res.json({
    success: true,
    eligibility: {
      status: 'available_to_apply',
      minAmount: limits.min,
      maxAmount: limits.max,
      subjectToFinalVerification: true
    }
  });
});

app.post('/api/applications', (req, res) => {
  const { service = 'Pawa Loans', amount, identity, repaymentPeriod } = req.body || {};
  const numericAmount = Number(amount);
  const limits = limitsFor();
  const validPeriods = [1, 2, 3, 6, 12];

  if (!Number.isInteger(numericAmount) || numericAmount < limits.min || numericAmount > limits.max) {
    return res.status(400).json({ success: false, message: 'Invalid loan amount.' });
  }
  if (!validPeriods.includes(Number(repaymentPeriod))) {
    return res.status(400).json({ success: false, message: 'Invalid repayment period.' });
  }
  if (!validIdentity(identity)) {
    return res.status(400).json({ success: false, message: 'Complete and valid identity information is required.' });
  }

  const reference = createReference();
  const fee = calculateFee(numericAmount);
  const application = {
    reference,
    service,
    amount: numericAmount,
    fee,
    repaymentPeriod: Number(repaymentPeriod),
    identity: {
      firstName: identity.firstName.trim(),
      lastName: identity.lastName.trim(),
      phone: normalisePhone(identity.phone),
      country: identity.country,
      town: identity.town.trim()
    },
    status: 'received',
    createdAt: new Date().toISOString()
  };

  applications.set(reference, application);
  res.status(201).json({ success: true, application: { reference, status: application.status, fee } });
});

app.post('/paystack/initialize', async (req, res) => {
  try {
    if (!PAYSTACK_SECRET_KEY) {
      return res.status(503).json({ status: false, message: 'Paystack is not configured. Add PAYSTACK_SECRET_KEY to the server environment.' });
    }

    const { phone, amount, applicationReference } = req.body || {};
    const normalizedPhone = normalisePhone(phone);
    const application = applications.get(applicationReference);

    if (!application) return res.status(404).json({ status: false, message: 'Application not found.' });
    if (application.status === 'payment_success') return res.status(409).json({ status: false, message: 'This application has already been paid.' });
    if (!normalizedPhone) return res.status(400).json({ status: false, message: 'Enter a valid Kenyan M-PESA number.' });

    const expectedFee = calculateFee(application.amount);
    const requestedAmount = Number(amount);
    if (!Number.isInteger(requestedAmount) || requestedAmount !== expectedFee) {
      return res.status(400).json({ status: false, message: 'Payment amount does not match the application fee.' });
    }

    const reference = `PWL-${application.reference}-${Date.now()}`;
    const email = `customer_${normalizedPhone.replace(/\D/g, '')}@example.com`;

    const response = await axios.post(
      'https://api.paystack.co/charge',
      {
        email,
        amount: expectedFee * 100,
        currency: 'KES',
        reference,
        metadata: {
          application_reference: application.reference,
          service: application.service,
          loan_amount: application.amount,
          fee_rate: FEE_RATE
        },
        mobile_money: {
          phone: normalizedPhone,
          provider: 'mpesa'
        }
      },
      {
        headers: {
          Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
          'Content-Type': 'application/json'
        },
        timeout: 20000
      }
    );

    const data = response.data;
    if (!data.status) return res.status(400).json(data);

    payments.set(reference, {
      reference,
      applicationReference: application.reference,
      amountSubunit: expectedFee * 100,
      status: data.data?.status || 'pending',
      createdAt: new Date().toISOString()
    });

    application.paymentReference = reference;
    application.status = data.data?.status === 'success' ? 'payment_success' : 'payment_pending';

    res.json({ status: true, message: data.message, data: data.data });
  } catch (error) {
    const payload = error.response?.data;
    res.status(error.response?.status || 500).json({
      status: false,
      message: payload?.message || error.message || 'Unable to initiate M-PESA payment.'
    });
  }
});

app.get('/paystack/verify/:reference', async (req, res) => {
  try {
    if (!PAYSTACK_SECRET_KEY) return res.status(503).json({ status: false, message: 'Paystack is not configured.' });

    const reference = req.params.reference;
    const payment = payments.get(reference);
    if (!payment) return res.status(404).json({ status: false, message: 'Payment reference not found.' });

    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` }, timeout: 20000 }
    );

    const data = response.data;
    const paidAmount = Number(data.data?.amount || 0);
    if (data.data?.status === 'success' && paidAmount !== payment.amountSubunit) {
      return res.status(400).json({ status: false, message: 'Verified payment amount does not match the expected fee.' });
    }

    payment.status = data.data?.status || payment.status;
    payment.updatedAt = new Date().toISOString();

    const application = applications.get(payment.applicationReference);
    if (application && payment.status === 'success') application.status = 'payment_success';

    res.json(data);
  } catch (error) {
    const payload = error.response?.data;
    res.status(error.response?.status || 500).json({
      status: false,
      message: payload?.message || error.message || 'Unable to verify payment.'
    });
  }
});

app.use(express.static(path.join(__dirname)));

app.listen(PORT, () => {
  console.log(`Pawa Loans server running on port ${PORT}`);
  if (!PAYSTACK_SECRET_KEY) console.log('PAYSTACK_SECRET_KEY is not set. Payment endpoints are disabled until configured.');
});
