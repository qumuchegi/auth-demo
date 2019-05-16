import React,{useRef,useState,useEffect} from 'react'
import {axios_session,axios_JWT} from '../../axios.config'


function ModifyPassword(){

    const input = useRef()

    async function modify(){
       if(!input.current.value) return alert('请输入新密码')
       try{
           // 支持 session 的 axios 调用
           //let res = await axios_session().post('http://localhost:3002/modify',{newPassword:input.current.value})

           // 支持 JWT/OAuth2.0 的 axios 调用
           let res = await axios_JWT().post('http://localhost:3002/modify',{newPassword:input.current.value})
           
           if(res.data.code === 0)
               alert('密码修改成功')
       }catch(err){
           alert('没有授权 401')  
           console.log(err)
       }
    }
    async function logout(){
        /*
        // 授权方法为 session 时：
        let res = await axios_session().post('http://localhost:3002/logout')
        if(res.data.code === 0){
            history.back()
        }
        */

        // 授权方法为 JWT 时：
        localStorage.setItem('token','')
        history.back()

        
    }
    return(
        <div>
            <h2>修改密码，只有服务端授权才能修改成功</h2>
            <labe for='password-modify'>新密码</labe>
            <input type='text' ref={input}></input>
            <button onClick={modify}>修改</button>
            <button onClick={logout}>退登</button>
            
        </div>
    )
}
export default ModifyPassword