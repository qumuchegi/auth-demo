import React,{Component} from 'react'
import ReactDOM from 'react-dom'
import {Router,BrowserRouter } from 'react-router-dom';
import { Route,Switch} from 'react-router'
import Login from './pages/login/Login'
import Register from './pages/register/Register'
import ModifyUserInfo from './pages/modifyUserInfo/ModifyUserInfo'
import createBrowserHistory from 'history/createBrowserHistory'
const history = createBrowserHistory()

ReactDOM.render(
    <div>
        <Router history={history}>
          <Switch>
            <Route exact path='/' component={Login}></Route>
            <Route path='/register' component={Register}></Route>
            <Route path='/modifypassword' component={ModifyUserInfo}></Route>
          </Switch>
        </Router>
    </div>,
    document.getElementById('root')
)
 