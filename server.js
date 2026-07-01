'use strict';

require('dotenv').config();

const express          = require('express');
const helmet           = require('helmet');
const cors             = require('cors');
const rateLimit        = require('express-rate-limit');
const Stripe           = require('stripe');
const crypto           = require('crypto');
const fs               = require('fs');
const path             = require('path');
const { createClient } = require('@supabase/supabase-js');

/* ─── Stripe (lazy — non crasha se la chiave manca al boot) ─── */
let _stripe = null;
function getStripe() {
  if (!_stripe) {
    const key = process.env.STRIPE_SECRET_KEY;
    if (!key) throw new Error('STRIPE_SECRET_KEY non impostata nelle variabili d\'ambiente Vercel');
    _stripe = Stripe(key);
  }
  return _stripe;
}

/* ─── Supabase (opzionale) ─── */
const supabase = (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_KEY)
  ? createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY)
  : null;

/* ─── Template HTML: lettura diretta senza cache (garantisce env vars aggiornate) ─── */
function getTemplate(filename) {
  const candidates = [
    path.join(__dirname, filename),
    path.join(process.cwd(), filename),
  ];
  let raw = null;
  for (const p of candidates) {
    try { raw = fs.readFileSync(p, 'utf8'); break; } catch (_) {}
  }
  if (!raw) throw new Error('File HTML non trovato: ' + filename);
  return raw
    .replace(/%%META_PIXEL_ID%%/g,  process.env.META_PIXEL_ID          || '')
    .replace(/%%STRIPE_PK%%/g,      process.env.STRIPE_PUBLISHABLE_KEY || '');
}

/* ─── App ─── */
const app = express();
app.set('trust proxy', 1);

/* ─── Security Headers ─── */
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'", "'unsafe-inline'", 'js.stripe.com', 'connect.facebook.net'],
      frameSrc:    ['js.stripe.com', 'hooks.stripe.com'],
      connectSrc:  ["'self'", 'api.stripe.com', '*.facebook.com', '*.facebook.net'],
      imgSrc:      ["'self'", 'data:', 'q.stripe.com', '*.facebook.com'],
      styleSrc:    ["'self'", "'unsafe-inline'", 'fonts.googleapis.com'],
      fontSrc:     ["'self'", 'fonts.gstatic.com'],
    },
  },
}));

/* ─── CORS ─── */
app.use(cors({
  origin: function (origin, cb) {
    /* Permetti: nessuna origin (curl/server), localhost, tutti i *.vercel.app, dominio custom */
    if (!origin) return cb(null, true);
    const allowed = process.env.ALLOWED_ORIGIN || '';
    if (
      origin === allowed ||
      origin === 'http://localhost:3000' ||
      /\.vercel\.app$/.test(origin)
    ) return cb(null, true);
    cb(new Error('CORS: origin non permessa: ' + origin));
  },
  methods: ['GET', 'POST'],
}));

/* ─── Health check (debug) ─── */
app.get('/api/health', function (req, res) {
  res.json({
    ok:      true,
    stripe:  !!process.env.STRIPE_SECRET_KEY,
    pk:      !!process.env.STRIPE_PUBLISHABLE_KEY,
    baseUrl: process.env.BASE_URL || null,
    supabase:!!process.env.SUPABASE_URL,
    pixel:   !!process.env.META_PIXEL_ID,
  });
});

/* ─── Rate limiting ─── */
const trackLimiter = rateLimit({
  windowMs:        60 * 1000,
  max:             60,
  standardHeaders: true,
  legacyHeaders:   false,
});
const checkoutLimiter = rateLimit({
  windowMs:        15 * 60 * 1000,
  max:             30,
  standardHeaders: true,
  legacyHeaders:   false,
  message:         { error: 'Troppe richieste. Riprova tra qualche minuto.' },
});

/* Raw body solo per il webhook Stripe (deve venire prima di express.json) */
app.use('/api/webhook', express.raw({ type: 'application/json' }));
app.use(express.json({ limit: '10kb' }));

/* ─── Route: HTML con variabili iniettate ─── */
function serveTemplate(filename) {
  return function (req, res) {
    try {
      res.set('Cache-Control', 'no-store');
      res.type('html').send(getTemplate(filename));
    } catch (e) {
      console.error('[Template]', e.message);
      res.status(500).send('Errore interno — riprova tra poco.');
    }
  };
}
app.get('/',             serveTemplate('index.html'));
app.get('/index.html',   serveTemplate('index.html'));
app.get('/success.html', serveTemplate('success.html'));
app.get('/admin',        serveTemplate('admin.html'));

/* ─── File statici ─── */
app.use(express.static(path.join(__dirname), { index: false }));

/* ─── Helpers ─── */
function sha256(value) {
  return crypto.createHash('sha256').update(value.trim().toLowerCase()).digest('hex');
}

async function saveEvent(eventName, step, stepName, payload) {
  if (!supabase) return;
  try {
    const { error } = await supabase.from('events').insert({
      event_name: eventName,
      step:       step,
      step_name:  stepName,
      payload:    payload,
    });
    if (error) console.error('[Supabase event]', error.message);
    else console.log('[Supabase] evento salvato:', eventName);
  } catch (e) {
    console.error('[Supabase event]', e.message);
  }
}

async function sendCapiEvent(eventName, eventId, userData, customData, sourceUrl) {
  if (!process.env.META_PIXEL_ID || !process.env.META_CAPI_TOKEN) return;

  const payload = {
    data: [{
      event_name:       eventName,
      event_time:       Math.floor(Date.now() / 1000),
      event_id:         String(eventId),
      event_source_url: sourceUrl || process.env.BASE_URL,
      action_source:    'website',
      user_data:        userData,
      custom_data:      customData,
    }],
    access_token: process.env.META_CAPI_TOKEN,
  };

  const response = await fetch(
    `https://graph.facebook.com/v19.0/${process.env.META_PIXEL_ID}/events`,
    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }
  );
  const result = await response.json();
  if (result.error) throw new Error(result.error.message);
  console.log('[Meta CAPI] ' + eventName + ' — eventi ricevuti: ' + result.events_received);
}

/* ─── POST /api/track ───────────────────────────────────────────────────────
   Traccia eventi browser (PageView, TimeOnPage) su Supabase.                  */
app.post('/api/track', trackLimiter, async function (req, res) {
  const { event, payload } = req.body;
  const allowed = ['PageView', 'TimeOnPage'];
  if (!allowed.includes(event)) return res.status(400).json({ error: 'Evento non valido' });

  await saveEvent(event, null, 'browser', {
    ...payload,
    ip:         req.ip,
    user_agent: req.get('user-agent') || '',
    referrer:   req.get('referer') || '',
  });
  res.json({ ok: true });
});

/* ─── GET /api/admin/stats ───────────────────────────────────────────────────
   Statistiche aggregate protette da ADMIN_PASSWORD.                           */
app.get('/api/admin/stats', async function (req, res) {
  const pwd = process.env.ADMIN_PASSWORD;
  if (pwd && req.query.password !== pwd) {
    return res.status(401).json({ error: 'Password non corretta' });
  }
  if (!supabase) return res.status(503).json({ error: 'Supabase non configurato' });

  try {
    const [
      { count: totalViews },
      { count: todayViews },
      { count: checkouts },
      { data: orders },
      { data: timeEvents },
      { data: dailyRaw },
    ] = await Promise.all([
      supabase.from('events').select('*', { count: 'exact', head: true }).eq('event_name', 'PageView'),
      supabase.from('events').select('*', { count: 'exact', head: true }).eq('event_name', 'PageView')
        .gte('created_at', new Date(Date.now() - 86400000).toISOString()),
      supabase.from('events').select('*', { count: 'exact', head: true }).eq('event_name', 'InitiateCheckout'),
      supabase.from('orders').select('amount, status, customer_email, paid_at, config').eq('status', 'succeeded').order('paid_at', { ascending: false }).limit(50),
      supabase.from('events').select('payload').eq('event_name', 'TimeOnPage').limit(500),
      supabase.from('events').select('created_at').eq('event_name', 'PageView')
        .gte('created_at', new Date(Date.now() - 7 * 86400000).toISOString()),
    ]);

    const completedOrders = orders || [];
    const revenue  = completedOrders.reduce(function (s, o) { return s + (o.amount || 0); }, 0);
    const avgSecs  = timeEvents && timeEvents.length
      ? Math.round(timeEvents.reduce(function (s, e) { return s + (e.payload?.seconds || 0); }, 0) / timeEvents.length)
      : 0;

    /* Visite per giorno (ultimi 7) */
    const dayMap = {};
    for (var i = 6; i >= 0; i--) {
      var d = new Date(Date.now() - i * 86400000);
      dayMap[d.toISOString().slice(0, 10)] = 0;
    }
    (dailyRaw || []).forEach(function (e) {
      var day = e.created_at.slice(0, 10);
      if (dayMap[day] !== undefined) dayMap[day]++;
    });

    res.json({
      views:     { total: totalViews || 0, today: todayViews || 0 },
      checkouts: checkouts || 0,
      sales:     { count: completedOrders.length, revenue: revenue },
      avgTime:   avgSecs,
      convCheckout: totalViews ? ((checkouts || 0) / totalViews * 100).toFixed(1) : '0.0',
      convSale:     (checkouts || 0) ? (completedOrders.length / (checkouts || 1) * 100).toFixed(1) : '0.0',
      daily:     dayMap,
      orders:    completedOrders.slice(0, 20),
    });
  } catch (err) {
    console.error('[Admin stats]', err.message);
    res.status(500).json({ error: err.message });
  }
});

/* ─── POST /api/create-payment-intent ───────────────────────────────────────
   Crea un PaymentIntent Stripe e restituisce il clientSecret al browser.
   Il secret key rimane esclusivamente lato server.                            */
app.post('/api/create-payment-intent', checkoutLimiter, async function (req, res) {
  const clientEventId = req.body.eventId;

  try {
    const paymentIntent = await getStripe().paymentIntents.create({
      amount:   3900,
      currency: 'eur',
      automatic_payment_methods: { enabled: true },
      description: 'Metodo Rituale Viso — Percorso completo',
      metadata:    { product: 'metodo-rituale-viso' },
    });

    /* CAPI: InitiateCheckout */
    sendCapiEvent(
      'InitiateCheckout',
      clientEventId || crypto.randomUUID(),
      { client_ip_address: req.ip, client_user_agent: req.get('user-agent') || '' },
      { value: 39.00, currency: 'EUR', content_ids: ['metodo-rituale-viso'], content_type: 'product', num_items: 1 },
      process.env.BASE_URL + '/#offerta'
    ).catch(e => console.error('[CAPI InitiateCheckout]', e.message));

    /* Supabase: evento checkout avviato */
    saveEvent('InitiateCheckout', 1, 'checkout_started', {
      payment_intent_id: paymentIntent.id,
      amount:            39.00,
      currency:          'EUR',
      ip:                req.ip,
      user_agent:        req.get('user-agent') || '',
      pixel_event_id:    clientEventId || null,
    });

    res.json({ clientSecret: paymentIntent.client_secret });

  } catch (err) {
    console.error('[Stripe Error]', err.message);
    res.status(500).json({ error: 'Si è verificato un errore. Riprova.', _debug: err.message });
  }
});

/* ─── GET /api/download-pdf ──────────────────────────────────────────────────
   Serve il PDF solo dopo aver verificato che il PaymentIntent sia succeeded.   */
app.get('/api/download-pdf', async function (req, res) {
  const { payment_intent } = req.query;

  if (!payment_intent || !payment_intent.startsWith('pi_')) {
    return res.status(400).send('Parametro mancante.');
  }

  try {
    const pi = await getStripe().paymentIntents.retrieve(payment_intent);
    if (pi.status !== 'succeeded') {
      return res.status(403).send('Pagamento non verificato.');
    }

    const pdfPath = path.join(__dirname, 'guida.pdf');
    if (!fs.existsSync(pdfPath)) {
      const alt = path.join(process.cwd(), 'guida.pdf');
      if (!fs.existsSync(alt)) return res.status(404).send('File non trovato.');
      return res.download(alt, 'Metodo-Rituale-Viso.pdf');
    }
    res.download(pdfPath, 'Metodo-Rituale-Viso.pdf');
  } catch (err) {
    console.error('[Download PDF]', err.message);
    res.status(500).send('Errore. Riprova.');
  }
});

/* ─── GET /api/purchase-confirm ─────────────────────────────────────────────
   Chiamato da success.html dopo il redirect di Stripe.
   Verifica il PaymentIntent e invia Purchase a Meta CAPI.                     */
app.get('/api/purchase-confirm', async function (req, res) {
  const { payment_intent, redirect_status } = req.query;

  if (!payment_intent || !payment_intent.startsWith('pi_')) {
    return res.status(400).json({ error: 'payment_intent non valido' });
  }
  if (redirect_status !== 'succeeded') {
    saveEvent('PurchaseFailed', 3, 'purchase_failed', {
      payment_intent_id: payment_intent,
      redirect_status,
      ip: req.ip,
    });
    return res.status(402).json({ error: 'Pagamento non completato' });
  }

  try {
    const pi = await getStripe().paymentIntents.retrieve(payment_intent, {
      expand: ['latest_charge'],
    });

    if (pi.status !== 'succeeded') {
      return res.status(402).json({ error: 'Pagamento non verificato' });
    }

    const eventId  = 'purchase_' + payment_intent;
    const billing  = pi.latest_charge?.billing_details;
    const userData = { client_ip_address: req.ip, client_user_agent: req.get('user-agent') || '' };

    if (billing?.email) userData.em = [sha256(billing.email)];
    if (billing?.name) {
      const parts = billing.name.trim().split(' ');
      if (parts[0])         userData.fn = [sha256(parts[0])];
      if (parts.length > 1) userData.ln = [sha256(parts.slice(1).join(' '))];
    }
    if (billing?.phone) userData.ph = [sha256(billing.phone.replace(/\s/g, ''))];

    sendCapiEvent(
      'Purchase', eventId, userData,
      { value: (pi.amount / 100).toFixed(2), currency: pi.currency.toUpperCase(), content_ids: ['metodo-rituale-viso'], content_type: 'product', content_name: 'Metodo Rituale Viso', num_items: 1, order_id: payment_intent },
      process.env.BASE_URL + '/success.html'
    ).catch(e => console.error('[CAPI Purchase]', e.message));

    /* ─── Salva ordine su Supabase ─── */
    if (supabase) {
      (async () => {
        try {
          /* evita duplicati (idempotente se success.html viene ricaricata) */
          const { data: existing } = await supabase
            .from('orders')
            .select('id')
            .eq('stripe_payment_id', payment_intent)
            .maybeSingle();

          if (!existing) {
            const { error } = await supabase.from('orders').insert({
              stripe_payment_id: payment_intent,
              amount:            pi.amount / 100,
              currency:          pi.currency.toUpperCase(),
              status:            pi.status,
              customer_email:    billing?.email || null,
              config: {
                customer_name:  billing?.name  || null,
                customer_phone: billing?.phone || null,
              },
              paid_at: new Date().toISOString(),
            });
            if (error) console.error('[Supabase insert]', error.message);
            else {
              console.log('[Supabase] ordine salvato:', payment_intent);
              /* evento acquisto completato */
              saveEvent('Purchase', 2, 'purchase_completed', {
                payment_intent_id: payment_intent,
                amount:            pi.amount / 100,
                currency:          pi.currency.toUpperCase(),
                customer_email:    billing?.email || null,
                customer_name:     billing?.name  || null,
                ip:                req.ip,
              });
            }
          } else {
            console.log('[Supabase] ordine già presente:', payment_intent);
          }
        } catch (e) {
          console.error('[Supabase]', e.message);
        }
      })();
    }

    res.json({ eventId, value: pi.amount / 100, currency: pi.currency.toUpperCase() });

  } catch (err) {
    console.error('[Purchase Confirm Error]', err.message);
    res.status(500).json({ error: 'Errore di verifica' });
  }
});

/* ─── POST /api/webhook ──────────────────────────────────────────────────────
   Riceve tutti gli eventi Stripe e li salva su Supabase.
   Configurare su: dashboard.stripe.com → Sviluppatori → Webhook             */
app.post('/api/webhook', async function (req, res) {
  const sig     = req.headers['stripe-signature'];
  const secret  = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    if (secret) {
      event = getStripe().webhooks.constructEvent(req.body, sig, secret);
    } else {
      /* senza secret accetta tutto — solo per sviluppo locale */
      event = JSON.parse(req.body.toString());
      console.warn('[Webhook] STRIPE_WEBHOOK_SECRET non impostato — firma non verificata');
    }
  } catch (err) {
    console.error('[Webhook] firma non valida:', err.message);
    return res.status(400).send('Webhook signature verification failed');
  }

  /* Salva l'evento grezzo su Supabase */
  saveEvent(event.type, null, 'stripe_webhook', {
    stripe_event_id: event.id,
    api_version:     event.api_version,
    object_id:       event.data?.object?.id    || null,
    object_type:     event.data?.object?.object || null,
    amount:          event.data?.object?.amount       ? event.data.object.amount / 100       : null,
    amount_received: event.data?.object?.amount_received ? event.data.object.amount_received / 100 : null,
    currency:        event.data?.object?.currency     ? event.data.object.currency.toUpperCase() : null,
    status:          event.data?.object?.status       || null,
    customer_email:  event.data?.object?.billing_details?.email
                  || event.data?.object?.receipt_email
                  || null,
    livemode:        event.livemode,
  });

  /* Azioni specifiche per tipo di evento */
  const obj = event.data?.object;

  switch (event.type) {

    case 'payment_intent.succeeded':
      if (supabase && obj?.id) {
        /* Aggiorna o crea l'ordine su Supabase */
        const { data: existing } = await supabase
          .from('orders').select('id').eq('stripe_payment_id', obj.id).maybeSingle();
        if (existing) {
          await supabase.from('orders')
            .update({ status: 'succeeded', paid_at: new Date().toISOString() })
            .eq('stripe_payment_id', obj.id);
        } else {
          await supabase.from('orders').insert({
            stripe_payment_id: obj.id,
            amount:            obj.amount / 100,
            currency:          obj.currency.toUpperCase(),
            status:            'succeeded',
            customer_email:    obj.receipt_email || null,
            config:            {},
            paid_at:           new Date().toISOString(),
          });
        }
        console.log('[Webhook] payment_intent.succeeded →', obj.id);
      }
      break;

    case 'payment_intent.payment_failed':
      if (supabase && obj?.id) {
        await supabase.from('orders')
          .update({ status: 'failed' })
          .eq('stripe_payment_id', obj.id);
        console.log('[Webhook] payment_intent.payment_failed →', obj.id);
      }
      break;

    case 'charge.refunded':
      if (supabase && obj?.payment_intent) {
        await supabase.from('orders')
          .update({ status: 'refunded' })
          .eq('stripe_payment_id', obj.payment_intent);
        console.log('[Webhook] charge.refunded →', obj.payment_intent);
      }
      break;

    case 'charge.dispute.created':
      console.warn('[Webhook] ⚠️  Disputa aperta:', obj?.id, '— controllare su Stripe dashboard');
      break;

    default:
      console.log('[Webhook] evento ricevuto:', event.type);
  }

  res.json({ received: true });
});

/* ─── 404 ─── */
app.use((req, res) => {
  try { res.status(404).type('html').send(getTemplate('index.html')); }
  catch (_) { res.status(404).send('Pagina non trovata'); }
});

/* ─── Avvio locale (non eseguito su Vercel) ─── */
if (!process.env.VERCEL) {
  const PORT = parseInt(process.env.PORT, 10) || 3000;
  const isLive = (process.env.STRIPE_SECRET_KEY || '').startsWith('sk_live');
  app.listen(PORT, function () {
    console.log('');
    console.log('  Metodo Rituale Viso — Server');
    console.log('  ─────────────────────────────────────────');
    console.log('  URL locale:  http://localhost:' + PORT);
    console.log('  Stripe:      ' + (isLive ? '🔴 MODALITÀ LIVE' : '🟡 MODALITÀ TEST'));
    console.log('  Meta Pixel:  ' + (process.env.META_PIXEL_ID   ? '✓ ' + process.env.META_PIXEL_ID  : '— non configurato'));
    console.log('  Meta CAPI:   ' + (process.env.META_CAPI_TOKEN ? '✓ token presente'                : '— non configurato'));
    console.log('  Supabase:    ' + (supabase                    ? '✓ connesso'        : '— non configurato'));
    console.log('  Webhook:     ' + (process.env.STRIPE_WEBHOOK_SECRET ? '✓ firma attiva'   : '⚠️  firma non verificata'));
    console.log('');
    if (isLive) {
      console.log('  ⚠️  ATTENZIONE: Stripe LIVE — i pagamenti sono reali.');
      console.log('');
    }
  });
}

/* ─── Export per Vercel serverless ─── */
module.exports = app;
