const axios = require('axios')

const OAuth=async (req,res,next)=>{
    let OAuth_token = req.headers["authorization"]
    console.log('authorization',OAuth_token)
    console.log('OAuth 中间件拿到cookie中的token：',OAuth_token)
    if(OAuth_token) {
        let token = OAuth_token.split('=')[1].replace('&scope','')
        let github_API_userInfo = await axios.get(`https://api.github.com/user?access_token=${token}`)
        let username = github_API_userInfo.data.name
        req.username = username
        next()
    }
    else res.status(401)
}
module.exports = OAuth