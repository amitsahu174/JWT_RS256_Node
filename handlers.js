const jwt = require('jsonwebtoken');
const fs = require('fs');
const jwtExpirySeconds = 30000

const privateKeyPath = './keys/opensshprivate.pem';
const publicKeyPath = './keys/opensshpub.pem';


var privateKey = fs.readFileSync(privateKeyPath, 'utf8');
var publicKey = fs.readFileSync(publicKeyPath, 'utf8');
//privateKey = Buffer.from(privateKey, 'base64')

const users = {
  user1: 'Amit@123',
  user2: 'Amit@123'
}

const signIn = (req, res) => {

  const { username, password } = req.body

  const token = jwt.sign({ sub: username }, privateKey, { algorithm: 'RS256', expiresIn: jwtExpirySeconds });

  res.send(token)

}

const welcome = (req, res) => {

  const token = req.headers.authorization


  if (!token || !token.startsWith('Bearer ')) {
    return res.status(401).end()
  }

  const authToken = token.split(' ')[1]

  var payload
  try {




    jwt.verify(authToken, publicKey, { algorithms: ['RS256'] })

  } catch (e) {
    if (e instanceof jwt.JsonWebTokenError) {

      return res.status(401).end()
    }

    return res.status(400).end()
  }



  res.send(`Welcome`)
}

const refresh = (req, res) => {

  const token = req.cookies.token

  if (!token) {
    return res.status(401).end()
  }

  var payload
  try {
    payload = jwt.verify(token, jwtKey)
  } catch (e) {
    if (e instanceof jwt.JsonWebTokenError) {
      return res.status(401).end()
    }
    return res.status(400).end()
  }





  const nowUnixSeconds = Math.round(Number(new Date()) / 1000)
  if (payload.exp - nowUnixSeconds > 30) {
    return res.status(400).end()
  }


  const newToken = jwt.sign({ username: payload.username }, jwtKey, {
    algorithm: 'HS512',
    expiresIn: jwtExpirySeconds
  })


  res.cookie('token', newToken, { maxAge: jwtExpirySeconds * 1000 })
  res.end()
}

const logout = (req, res) => {
  res.cookie('token', '', { maxAge: 0 })
  res.end()
}

module.exports = {
  signIn,
  welcome,
  refresh,
  logout
}
