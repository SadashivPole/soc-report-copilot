'use strict';

// Central error handler: maps thrown errors to JSON, hides internals in prod.
function errorHandler(err, req, res, _next) {
  const status = err.status || 500;
  if (status >= 500) console.error('[error]', err.message, err.stack);
  res.status(status).json({
    error: status >= 500 ? 'Internal server error' : err.message,
  });
}

function notFound(req, res) {
  res.status(404).json({ error: 'Not found' });
}

module.exports = { errorHandler, notFound };
