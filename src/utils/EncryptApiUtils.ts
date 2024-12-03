import request from "@/axios";
import type {AxiosResponse, InternalAxiosRequestConfig} from "axios";
import CryptoJS from 'crypto-js';

/**
 * 密钥和密文是否是 url 安全的
 */
let isUrlSafe = true

// 密钥形式是 base64：5syQuHi5SMNekrADx5LEbFjEr0C0a9GigIVgDr3oT_c=
let originKey: string = ''
let originIv: string = ''

let urlNotSafeKey: string
let urlNotSafeIv: string

/**
 * 处理接口加密
 * @param config 请求信息
 */
function handleApiEncrypt(config: InternalAxiosRequestConfig) {
    checkKey()
    // 根据请求传参是 data 还是 params，还有 FormData 形式，进行不同的参数处理方法
    if (config.params) {
        encryptParams(config)
    }
    if (config.data) {
        if (config.headers["Content-Type"] === 'multipart/form-data') {
            encryptFormData(config)
        } else {
            encryptData(config)
        }
    }
}

/**
 * 处理接口解密
 * @param response 响应信息
 */
function handleApiDecrypt(response: AxiosResponse) {
    checkKey()
    decryptData(response)
}

/**
 * 检查并获取密钥
 */
function checkKey() {
    // 前端没有存储密钥时，从服务器获取一下
    if (!originKey || !originIv) {
        getEncryptKey()
    }
}

/**
 * 从服务器请求密钥
 */
function getEncryptKey() {
    request({
        url: '/common/getEncryptKey',
        method: 'POST'
    }).then(successResponse => {
        const data = successResponse.data.data
        originKey = data.key
        originIv = data.iv
        isUrlSafe = data.isUrlSafe
    }).catch(() => {
        console.log('请求加解密密钥失败')
    })
}

/**
 * 根据前后端协商的密文密钥 base64 是否是 url 安全的进行密钥转换
 * @return 转换后的密钥
 */
function getKey() {
    let key = originKey
    let iv = originIv
    // 如果前后端协商的密文和密钥的 base64 是 url 安全的，需要把 base64 转换为 url 不安全的，因为 CryptoJS 不支持 url 安全的 base64 的处理
    if (isUrlSafe) {
        // 把转换的密钥 base64 保存起来，提高性能
        if (!urlNotSafeKey) {
            urlNotSafeKey = base64ToUrlNotSafe(originKey)
            urlNotSafeIv = base64ToUrlNotSafe(originIv)
        }
        key = urlNotSafeKey
        iv = urlNotSafeIv
        return {key, iv}
    }
    return {key, iv}
}

/**
 * 处理 param 参数加密
 * @param config 请求信息
 */
function encryptParams(config: InternalAxiosRequestConfig) {
    const {key, iv} = getKey()
    // 把请求 param 参数一个个取出来加密，替换 config 里面的 params
    const encryptParams: any = {}
    const params: any = config.params || {}
    for (let paramKey in params) {
        encryptParams[paramKey] = encrypt(String(params[paramKey]), key, iv)
    }
    // 替换请求里的 params
    config.params = encryptParams
}

/**
 * 处理 formData 参数加密
 * @param config 请求信息
 */
function encryptFormData(config: InternalAxiosRequestConfig) {
    const {key, iv} = getKey()
    // 创建一个 FormData 存储加密后的参数
    const encryptFormData = new FormData()
    // 取出请求里的 FormData，转换为对象，便于判断对象内各字段的数据类型
    const formData = config.data || {}
    const obj: any = {};
    for (const dataKey of formData.keys()) {
        obj[dataKey] = formData.getAll(dataKey).length > 1 ? formData.getAll(dataKey) : formData.get(dataKey);
    }
    // 遍历对象，把字段一个个加密后塞进上面新创建的 FormData
    for (let objKey in obj) {
        // 字段值
        const value = obj[objKey]
        // 即将放入上面新创建的 FormData 的值
        let formDataValue
        // 文件类型暂不处理，因为 SecureApi 组件还没有处理文件解密的能力
        if (value instanceof Array && value[0] instanceof File) {
            value.forEach(file => {
                encryptFormData.append(objKey, file)
            })
        } else {
            if (value instanceof File) {
                formDataValue = value
            } else if (value instanceof Object || value instanceof Array || value instanceof Set || value instanceof Map) {
                // 这些类型需要转换为 json 字符串再加密
                formDataValue = encrypt(JSON.stringify(value), key, iv)
            } else {
                // 其余基本类型不能转换为 json 字符串，因为 json 字符串两边会加上双引号，如 int 类型的 1，变为 "1" 后，后端就会序列化失败
                formDataValue = encrypt(value, key, iv)
            }
            encryptFormData.append(objKey, formDataValue as any)
        }
    }
    // 替换请求里的 data
    config.data = encryptFormData
}

/**
 * 处理 data 参数加密
 * @param config 请求信息
 */
function encryptData(config: InternalAxiosRequestConfig) {
    const {key, iv} = getKey()
    // 请求 data 是对象，转换为 json 字符串后再加密，然后替换 config 的 data
    config.data = encrypt(JSON.stringify(config.data), key, iv)
}

/**
 * 处理 json 返回值解密
 * @param response 响应信息
 */
function decryptData(response: AxiosResponse) {
    if (response.data) {
        const {key, iv} = getKey()
        const decryptData = decrypt(response.data, key, iv)
        // 返回值是 json 字符串，转换为对象后替换 response 的 data
        response.data = JSON.parse(decryptData)
    }
}

/**
 * 加密数据
 * @param data 要加密的数据，必须是 String 类型，普通类型抓换为 String 使用 String(data)，对象使用 JSON.stringify(data)
 * @param AES_KEY 密钥（base64）
 * @param IV 偏移量（base64）
 * @return 加密结果（base64）
 */
function encrypt(data: string, AES_KEY: string, IV: string) {
    let encryptResult
    // 把 base64 转换成 CryptoJS.lib.WordArray
    const key = CryptoJS.enc.Base64.parse(AES_KEY);
    if (IV) {
        const iv = CryptoJS.enc.Base64.parse(IV);
        encryptResult = CryptoJS.AES.encrypt(data, key, {
            iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7,
        });
    } else {
        encryptResult = CryptoJS.AES.encrypt(data, key, {
            mode: CryptoJS.mode.ECB,
            padding: CryptoJS.pad.Pkcs7,
        });
    }
    // 默认就是base64
    const result = encryptResult.toString()
    // CryptoJS 处理的 base64 都是 url 不安全的，要进行转换
    return isUrlSafe ? base64ToUrlSafe(result) : result;
}

/**
 * 解密数据
 * @param data 要解密的数据（base64）
 * @param AES_KEY 密钥（base64）
 * @param IV 偏移量（base64）
 * @return 解密结果（UTF8字符串）
 */
function decrypt(data: string, AES_KEY: string, IV: string) {
    // CryptoJS 不支持处理 url 安全的 base64，所以要转换为 url 不安全的以后再进行解密
    data = isUrlSafe ? base64ToUrlNotSafe(data) : data
    let decryptResult
    // 把 base64 转换成 CryptoJS.lib.WordArray
    const key = CryptoJS.enc.Base64.parse(AES_KEY);
    if (IV) {
        const iv = CryptoJS.enc.Base64.parse(IV);
        decryptResult = CryptoJS.AES.decrypt(data, key, {
            iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7,
        });
    } else {
        decryptResult = CryptoJS.AES.decrypt(data, key, {
            mode: CryptoJS.mode.ECB,
            padding: CryptoJS.pad.Pkcs7,
        });
    }
    // 转换为 UTF-8 格式的字符串
    return decryptResult.toString(CryptoJS.enc.Utf8);
}

/**
 * 解码 URL Safe base64 -> base64
 * '-' -> '+'
 * '_' -> '/'
 * 字符串长度 %4,补 =
 * @param base64Str base64字符串
 * @return url 不安全的 base64
 */
function base64ToUrlNotSafe(base64Str: string): string {
    if (!base64Str) return '';
    let safeStr = base64Str.replace(/-/g, '+').replace(/_/g, '/');
    let num = safeStr.length % 4;
    return safeStr + '===='.substring(0, num);
}

/**
 * 编码 base64 -> URL Safe base64
 * '+' -> '-'
 * '/' -> '_'
 * '=' -> ''
 * @param base64Str base64字符串
 * @return url 安全的 base64;
 */
function base64ToUrlSafe(base64Str: string): string {
    if (!base64Str) return '';
    //.replace(/=+$/, '')，等号无需处理
    return base64Str.replace(/\+/g, '-').replace(/\//g, '_')
}

export {handleApiEncrypt, handleApiDecrypt}
