// app.js
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const pool = require('./db');
require('dotenv').config();

const app = express();
app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(helmet());


const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120
});
app.use(limiter);

const csrfProtection = csrf({ cookie: true });

let sqlVulnerable = true;
let csrfVulnerable = true;



app.get('/', csrfProtection, (req, res) => {
  const token = csrfVulnerable ? '' : req.csrfToken();

  res.render('index', {
    sqlVulnerable,
    csrfVulnerable,
    csrfToken: token,
    sqlResult: null,
    csrfMessage: null
  });
});


app.post('/sql-vuln', async (req, res) => {
  sqlVulnerable = req.body.vulnerable === 'on';
  const username = req.body.username || '';

  let result = null;

  if (sqlVulnerable) {
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    try {
      const { rows } = await pool.query(query);
      result = rows;
    } catch (err) {
      result = `Error: ${err.message}`;
    }
  } else {
    result = 'Ranjivost isključena.';
  }

  // generiraj token samo za siguran prikaz
  const token = csrfVulnerable ? '' : req.csrfToken ? req.csrfToken() : '';
  res.render('index', {
    sqlVulnerable,
    csrfVulnerable,
    csrfToken: token,
    sqlResult: result,
    csrfMessage: null
  });
});

// SIGURNA ruta - parametrizirani upit
app.post('/sql', async (req, res) => {
  // checkbox šalje 'on' kad je označeno
  sqlVulnerable = req.body.vulnerable === 'on';
  const username = req.body.username || '';

  let result = null;

  if (!sqlVulnerable) {
    try {
      const { rows } = await pool.query(
        'SELECT * FROM users WHERE username = $1',
        [username]
      );
      result = rows;
    } catch (err) {
      result = `Error: ${err.message}`;
    }
  } else {
    result = 'Aplikacija postavljena u ranjiv način (sql).';
  }

  const token = csrfVulnerable ? '' : req.csrfToken ? req.csrfToken() : '';
  res.render('index', {
    sqlVulnerable,
    csrfVulnerable,
    csrfToken: token,
    sqlResult: result,
    csrfMessage: null
  });
});



app.post('/csrf', csrfProtection, (req, res) => {
  csrfVulnerable = req.body.vulnerable === 'on';
  const action = req.body.action || '';

  let message = `Akcija "${action}" uspješno izvršena! (sigurno)`;

  const token = csrfVulnerable ? '' : req.csrfToken ? req.csrfToken() : '';
  res.render('index', {
    sqlVulnerable,
    csrfVulnerable,
    csrfToken: token,
    sqlResult: null,
    csrfMessage: message
  });
});

app.post('/csrf-vuln', (req, res) => {
  csrfVulnerable = req.body.vulnerable === 'on';
  const action = req.body.action || '';

  let message = csrfVulnerable
    ? `Akcija "${action}" uspješno izvršena! (ranjivo)`
    : 'Ranjivost isključena (csrf-vuln).';

  const token = csrfVulnerable ? '' : req.csrfToken ? req.csrfToken() : '';
  res.render('index', {
    sqlVulnerable,
    csrfVulnerable,
    csrfToken: token,
    sqlResult: null,
    csrfMessage: message
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server pokrenut na portu ${PORT}`));
