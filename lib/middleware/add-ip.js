module.exports = app => {
  const addIP = (req, res, next) => {
    // `x-real-ip` is for when is behind an nginx reverse proxy
    // `x-forwarded-for` is for receiving requests behind an ngrok proxy
    req.feathers.ip = req.headers['x-real-ip'] || req.headers['x-forwarded-for'] || req.ip
    // carry on...
    next()
  }
  app.use(addIP)
}