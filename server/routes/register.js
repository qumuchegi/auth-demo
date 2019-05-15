const getModel = require('../db').getModel
const router = require('express').Router();
const users = getModel('users')

router.post('/', (req,res,next)=>{
    let {username, password} = req.body
    console.log(username)
    users.findOne({username},(err,olduser)=>{
        if(olduser){
            res.send({code:1})// 已有相同用户名
        }else{
            new users({username, password})
            .save((err,newuser)=>{
                res.send({code:0})// 注册成功
            })
        }
    })
})

module.exports = router