const getModel = require('../db').getModel
const router = require('express').Router()
const users = getModel('users')
const JWT = require('jsonwebtoken')
const secret = require('../server.config').JWT_config.secret
const algorithm = require('../server.config').JWT_config.algorithm
const Auth_github = require('../server.config').Auth_github
const axios = require('axios')


// 使用 session/JWT 】时的登录接口
router.post('/', (req,res,next)=>{
    let {username, password } = req.body  
    console.log(username, password)
     
        users.findOne({username},(err,olduser)=>{
            if(!olduser){
                res.send({code:1})// 没有该用户
            }else{
                if(olduser.password === password){// 密码正确
     
                    /*
                    
                    // 授权方法 1. session 
                    req.session.username = olduser.username
                    req.session.userID = olduser._id
                    console.log('登录时的会话 ID：',req.sessionID)
                    req.session.cookie.maxAge = 60*60*1000
                    req.session.save()
                    res.send({code:0})// 登录成功
    
                    */
    
                    // 授权方法 2. JWT
                    let token = JWT.sign(
                        {username:olduser.username, exp:Date.now() + 1000 * 60}, // payload
                        secret, // 签名密钥
                        {algorithm} // 签名算法
                    )
                    res.send({
                        code:0,
                        token
                    })
                    
                }else{
    
                    res.send({code:2}) // 密码错误
                }
            }
        })
     
})




 
 
// 使用 OAuth2.0 时的登录接口，
router.get('/callback',async (req,res,next)=>{//这是一个授权回调，用于获取授权码 code
    var code = req.query.code; // GitHub 回调传回 code 授权码
    console.log(code)
    
    // 带着 授权码code、client_id、client_secret 向 GitHub 认证服务器请求 token
    let res_token = await axios.post('https://github.com/login/oauth/access_token',
    {
        client_id:Auth_github.client_id,
        client_secret:Auth_github.client_secret,
        code:code
    })
   console.log(res_token.data)

   let token = res_token.data.split('=')[1].replace('&scope','')
   

   // 带着 token 从 GitHub 获取用户信息
   let github_API_userInfo = await axios.get(`https://api.github.com/user?access_token=${token}`)
   console.log('github 用户 API：',github_API_userInfo.data)

   let userInfo = github_API_userInfo.data

   // 用户使用 GitHub 登录后，在数据库中存储 GitHub 用户名
   users.findOne({username:userInfo.name},(err,oldusers)=>{ // 看看用户之前有没有登录过，没有登录就会在数据库中新增 GitHub 用户
    if(oldusers) {
        res.cookie('auth_token',res_token.data)
        res.cookie('userAvatar',userInfo.avatar_url)
        res.cookie('username',userInfo.name)

        res.redirect(301,'http://localhost:8082') // 从GitHub的登录跳转回我们的客户端页面
        return
    }else
    new users({
        username:userInfo.name,
        password:'123', // 为使用第三方登录的能够用户初始化一个密码，后面用户可以自己去修改
    }).save((err,savedUser)=>{
        if(savedUser){
            res.cookie('auth_token',res_token.data)
            res.cookie('userAvatar',userInfo.avatar_url)
            res.cookie('username',userInfo.name)
         
            res.redirect(301,'http://localhost:8082') // 从GitHub的登录跳转回我们的客户端页面
        }
    })
   })
},
)
module.exports = router