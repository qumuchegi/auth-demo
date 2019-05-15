const JWT = require('jsonwebtoken')
const secret = require('../server.config').JWT_config.secret
const algorithm = require('../server.config').JWT_config.algorithm


function JWT_auth(req,res,next){
    let authorization = req.headers["authorization"]
    console.log('authorization',authorization)
    if(authorization)
    try{
        let token = authorization;
        JWT.verify(token,secret,{algorithm:'HS256'},(err,decoded)=>{ // 用户认证
            if(err){
                console.log(err)
                next(err)
            }else{
                console.log(decoded)
                req.username = decoded.username // 在 req 上添加 username,以便于传到下一个中间件取出 username 来查询数据库
                next()
            }
        })

    }catch(err){
        res.status(401).send("未授权");
    }
    else
    res.status(401).send("未授权");
}
module.exports = JWT_auth