const http = require('http')
const express = require('express')
const cors = require('cors')
const session = require('express-session')
const cookieParser = require('cookie-parser')

const app = express()

app.use(express.json());
app.use(cookieParser())
app.use(express.urlencoded({ extended: false }));
 


// 跨域
app.use(cors({
    //使用 session 时的 cors 配置
    credentials: true, 
    origin: 'http://localhost:8082', // web前端页面的服务器地址，不能设置为 * 
   
}))
 

// session

app.use(session({
    secret: '123456789',
    unset:'destroy',// 在每次会话就熟后销毁 session
    resave:true,
    saveUninitialized:false,
    rolling:true,
    cookie:{
        maxAge:60*60*1000
    }

}))


// 路由目录
//app.use('/user',require('./routes/user'))
app.use('/register',require('./routes/register'))
app.use('/login',require('./routes/login'))
app.use('/modify',require('./routes/modifyPassword'))
app.use('/logout',require('./routes/logout'))


 


const server = http.createServer(app)
server.listen(3002,()=> console.log('服务启动...'))