/**
 * Below IP addresses retrieved on 2019-10-05 from:
 * https://auth0.com/docs/guides/ip-whitelist
 */
const usIPAddresses = [
  '35.167.74.121',
  '35.166.202.113',
  '35.160.3.103',
  '54.183.64.135',
  '54.67.77.38',
  '54.67.15.170',
  '54.183.204.205',
  '35.171.156.124',
  '18.233.90.226',
  '3.211.189.167'
]
const euIPAddresses = [
  '52.28.56.226',
  '52.28.45.240',
  '52.16.224.164',
  '52.16.193.66',
  '34.253.4.94',
  '52.50.106.250',
  '52.211.56.181',
  '52.213.38.246',
  '52.213.74.69',
  '52.213.216.142',
  '35.156.51.163',
  '35.157.221.52',
  '52.28.184.187',
  '52.28.212.16',
  '52.29.176.99',
  '52.57.230.214',
  '54.76.184.103',
  '52.210.122.50',
  '52.208.95.174',
  '52.210.122.50',
  '52.208.95.174',
  '54.76.184.103'
]
const auIPAddresses = [
  '52.64.84.177',
  '52.64.111.197',
  '54.153.131.0',
  '13.210.52.131',
  '13.55.232.24',
  '13.54.254.182',
  '52.62.91.160',
  '52.63.36.78',
  '52.64.120.184',
  '54.66.205.24',
  '54.79.46.4'  
]
const fromAuth0 = ({
  whitelist = usIPAddresses
} = {}) => context => {
  // get the app from the context
  const { app } = context
  // get the Auth0 configuration from the app
  const { auth0: config } = app.get('authentication')
  // declare a variable to hold our whitelist
  let list
  // has a whitelist been specified as an array?
  if (Array.isArray(config.whitelist) && config.whitelist.length > 0) {
    // yes, so use it, as specified
    list = config.whitelist
  } else if (config.whitelist && typeof config.whitelist === 'string') {
    // the whitelist was specified as a string
    switch (config.whitelist.toLowerCase()) {
    case 'eu': list = euIPAddresses; break
    case 'au': list = auIPAddresses; break
    default: list = usIPAddresses
    }
  } else {
    // unspecified, default to US
    list = whitelist
  }
  // check to see that the current IP address is whitelisted
  return list.includes(context.params.ip)
}

module.exports = {
  fromAuth0,
  usIPAddresses,
  euIPAddresses,
  auIPAddresses
}
