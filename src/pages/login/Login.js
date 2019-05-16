import React,{useState} from 'react'
import {Link} from 'react-router-dom'

// 使用 session 或者 JWT 是使用配置好的 axios
//import {axios_session,axios_JWT} from  '../../axios.config'

// 使用 OAuth2.0 时引入原生 axios
import axios from 'axios'

function Login(){
    const [username, setUsername] = useState()
    const [password, setPassword] = useState()
    const [loginSeccess, setLoginSeccess] = useState(false)

    async function login(){
        // 支持 session 的 axios 调用
        //let res = await axios_session().post('http://localhost:3002/login',{username,password})

        // 支持 JWT 的 axios 调用
        let res = await axios_JWT().post('http://localhost:3002/login',{username,password,authByOAuth2:false})

        if(res.data.code === 0){
            /*

            // 授权方法 为 session 时用这段代码：
            setLoginSeccess(true)
            alert('登录成功,请修改密码')

            */

            //  授权方法 为 JWT 时用这段代码：
            setLoginSeccess(true)
            alert('登录成功,请修改密码')
            console.log(res.data.token)
            localStorage.setItem('token',res.data.token)
            
        }else if(res.data.code === 2){
            alert('密码不正确')
            return
        }else if(res.data.code === 1){
            alert('没有该用户')
            return
        }
    }
    const inputChange = (k,v) =>{
        if(k==='name'){
            setUsername(v)
        }else if(k === 'password'){
            setPassword(v)
        }
    }
    
   
    return(
        <div>
            <h1>登录</h1>
            <div id='form'>
               <label for='usernameInput'>用户名</label>
               <input type='text' 
                      onChange={(e) => inputChange('name',e.target.value)}
                      name='usernameInput'></input>
               <label for='passwordInput'>密码</label>
               <input type='text' 
                      onChange={(e) => inputChange('password',e.target.value)}
                      name='passwordInput'></input>
            </div>
            <button onClick={login}>登录</button>
            <br/>
            <Link to='/modifyPassword'>修改密码</Link>
            <br/>
            <Link to='/register'>去注册</Link>
            <br/>
            <a href='https://github.com/login/oauth/authorize?client_id=211383cc22d28d9dac52'> 使用 GitHub 账号登录 </a>
            {
                document.cookie ?
                <div>
                    <h4>已经使用GitHub 账号登录</h4>
                    <span>GitHub 用户名：
                       {decodeURIComponent(document.cookie.split(';').filter(e=>/username/.test(e))[0].replace(/username=/,''))}
                   </span>
                    <img src={unescape(document.cookie.split(';').filter(e=>/userAvatar/.test(e))[0].replace(/userAvatar=/,''))}  
                         style={{width:'50px',height:'50px',borderRadius:'50px'}} alt=''></img>
                </div>
                :
                null
            }
        </div>
    )
}
export default Login
