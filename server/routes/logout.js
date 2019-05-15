
const router = require('express').Router()
 
router.post('/', (req,res,next)=>{
    req.session.destroy(()=>console.log('销毁session，已经推出登录'))
    res.send({code:0})
})

module.exports = router