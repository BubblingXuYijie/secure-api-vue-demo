/**
 * axios封装
 * 请求拦截、相应拦截，处理加解密
 */
import axios from "axios";
import {handleApiEncrypt, handleApiDecrypt} from "@/utils/EncryptApiUtils";

// 创建axios实例
const service = axios.create({
    baseURL: '/',
    headers: {'Content-Type': 'application/json;charset=UTF-8'},
})

// 请求拦截器
service.interceptors.request.use(config => {
    // 处理接口加密
    handleApiEncrypt(config);
    return config;
}, error => {
    return Promise.reject(error);
})

// 响应拦截器
service.interceptors.response.use(response => {
        // 处理接口解密
        handleApiDecrypt(response);
        if (response.status === 200) {
            return Promise.resolve(response);
        }
        return Promise.reject(response);
    },
    // 服务器状态码不是200的情况
    error => {
        console.log('请求出错：' + error)
        return Promise.reject(error);
    }
);

export default service
