module.exports = app => {
  const addIP = (req, res, next) => {
    // `x-real-ip` is for when is behind an nginx reverse proxy
    req.feathers.ip = req.headers['x-real-ip'] || req.ip
    // carry on...
    next()
  }
  app.use(addIP)
}