const path = require("path")
const webpack = require("webpack")
const VueLoaderPlugin = require('vue-loader/lib/plugin')

module.exports = {
    entry: {
        app: './src/index.js',
    },
    plugins: [
        new webpack.LoaderOptionsPlugin({
            options: {
                alias: {
                    "@": path.resolve("src"),
                    "@auth": path.resolve("src/authenticate"),
                    "@composents": path.resolve("composents")
                },
            }
        }),
        new VueLoaderPlugin()
    ],
    output: {
        filename: '[name].bundle.js',
        path: path.resolve(__dirname, 'dist')
    },
    module: {
        rules: [{
                test: /\.css$/,
                use: [
                    'style-loader',
                    'css-loader'
                ]
            },
            {
                test: /\.(woff|woff2|eot|ttf|otf)$/,
                use: [
                    'file-loader'
                ]
            },
            {
                test: /\.vue$/,
                use: [
                    'vue-loader'
                ]
            },
        ]
    }
};