import React,{useState,useEffect} from 'react'
import axios from 'axios'

function Register(){
    const [username, setUsername] = useState()
    const [password, setPassword] = useState()

    const inputChange = (k,v) =>{
        if(k==='name'){
            setUsername(v)
        }else if(k === 'password'){
            setPassword(v)
        }
    }
    async function register(){
        let res = await axios.post('http://localhost:3002/register',{username,password})
        console.log(res)
        if(res.data.code === 0){
            alert('注册成功')
        }else{
            alert('有相同用户名')
        }
    }
    return(
        <div>
            <h2>注册</h2>
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
            <button onClick={register}>注册</button>
        </div>
    )

}
export default Register