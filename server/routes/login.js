const getModel = require('../db').getModel
const router = require('express').Router()
const users = getModel('users')
const JWT = require('jsonwebtoken')
const secret = require('../server.config').JWT_config.secret
const algorithm = require('../server.config').JWT_config.algorithm

router.post('/', (req,res,next)=>{
    let {username, password} = req.body
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

module.exports = router