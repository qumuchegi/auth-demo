const getModel = require('../db').getModel
const router = require('express').Router()
const users = getModel('users')
const sessionAuth = require('../middlewere/sessionAuth') 
const JWT_auth = require('../middlewere/JWTAuth')
const OAuth = require('../middlewere/OAuth')
 

router.post('/',
    //sessionAuth, // 使用 session 授权时用这个中间件
    //JWT_auth,// 使用 jwt 授权时用这个中间件
   
    OAuth,// 使用 OAuth 2.0 授权时用这个中间件
    (req,res,next)=>{

    let {newPassword} = req.body
    //console.log('修改密码时的会话 ID：',req.session.id)

    // 授权方法为 session 或者 OAuth2.0 时：
    if(req.session.username){
        users.findOne({username: req.session.username},(err,olduser)=>{
            olduser.password = newPassword
            olduser.save(err=>{
                if(!err){
                    res.send({code:0})// 修改密码成功
                }
            })
        })
    }

    // 授权方法为 JWT/OAuth2.0 时：
    if(req.username){
        console.log('JWT 用户验证通过 username:',req.username)
        users.findOne({username: req.username},(err,olduser)=>{
            if(olduser){
                console.log(olduser)
                olduser.password = newPassword
                olduser.save(err=>{
                    if(!err){
                        res.send({code:0})// 修改密码成功
                    }
                })
            }
        })
    }


})

module.exports = router