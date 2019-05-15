import React,{Component} from 'react'
import ReactDOM from 'react-dom'
import {Router,BrowserRouter } from 'react-router-dom';
import { Route,Switch} from 'react-router'
import Login from './pages/login/Login'
import Register from './pages/register/Register'
import ModifyUserInfo from './pages/modifyUserInfo/ModifyUserInfo'

ReactDOM.render(
    <div>
       <BrowserRouter> 
            <Switch>
                <Route exact path='/' component={Login}></Route>
                <Route path='/register' component={Register}></Route>
                <Route path='/modifypassword' component={ModifyUserInfo}></Route>
            </Switch>
        </BrowserRouter>
    </div>,
    document.getElementById('root')
)
 