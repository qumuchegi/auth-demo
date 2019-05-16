import axios from 'axios'

// 支持 express-session 的 axios 配置
export function axios_session(){
    axios.defaults.withCredentials = true
    return axios
}

// 支持 JWT/OAuth2.0 的 axios 配置
export  function axios_JWT(){
/*
    // JWT
    axios.interceptors.request.use(config => {
        // 在 localStorage 获取 token
        let token = localStorage.getItem("token");
        console.log('axios配置:token',token)
        // 如果存在则设置请求头
        if (token) {
            config.headers['Authorization'] = token;
            console.log(config)
        }
        return config;
    });
*/
    // OAuth2.0
    axios.interceptors.request.use(config => {
        // 在 localStorage 获取 token
        let token = localStorage.getItem("token");
        console.log('axios配置:token',token)
        // 如果存在则设置请求头
        if(document.cookie){
            let OAtuh_token = unescape(document.cookie.split(';').filter(e=>/auth_token/.test(e))[0].replace(/auth_token=/,''))
            config.headers['Authorization'] = OAtuh_token;
            console.log(config)
        }
       
        return config;
    });
   
    return axios
}

// 支持 OAuth 2.0 的 axios 配置


