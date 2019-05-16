const path = require('path')
const HtmlWebpackPlugin = require('html-webpack-plugin');
const CleanWebpackPlugin = require('clean-webpack-plugin');

module.exports = {
    mode:'production',
    entry:{
        app:'./src/index'
    },
    output:{
        filename:'[name].bundle.js',
        path:path.resolve(__dirname,'dist')
    },
    
    module:{
        rules:[
            {
                test:/\.(js|jsx)$/,
                exclude:/node_modules/,
                include:path.resolve(__dirname,'src'),
                use:'babel-loader',
                
            },
            {
                test:/\.css$/,
                include:path.resolve(__dirname,'src'),
                use: ['style-loader','css-loader']
            },

        ]
    },
    devtool: 'inline-source-map',
    devServer: {
        contentBase: path.join(__dirname, "dist"),
        compress: true,
        port: 8082,
        host: "localhost",
        hot: true
    },
    plugins:[
       
        new HtmlWebpackPlugin({
            title:'output management',
            template: "./src/index.html",
            filename: "./index.html"
        }),

       
    ]
}