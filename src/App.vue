<script setup lang="ts">
import CryptoJS from 'crypto-js';
import request from "@/axios";
import {ref} from "vue";

const data = ref('')
const isUrlSafe = ref(true)

const aesKey = ref('')
const aesIv = ref('')

const urlSafeKey = ref('')
const urlSafeIv = ref('')

const encryptData = ref('')
const decryptData = ref('')

const decryptResult = ref('')

function generateAesKeyAndIv() {
  // 对于 AES-256 使用 32，我们的 SecureApi 组件就是使用的 AES-256
  const key = CryptoJS.lib.WordArray.random(32).toString(CryptoJS.enc.Base64);
  // AES 的 IV 通常是 16 字节
  const iv = CryptoJS.lib.WordArray.random(16).toString(CryptoJS.enc.Base64);
  aesKey.value = key
  aesIv.value = iv
}

function convertKeyAndIvToUrlSafe() {
  urlSafeKey.value = base64ToUrlSafe(aesKey.value)
  urlSafeIv.value = base64ToUrlSafe(aesIv.value)
}

function inputChange() {
  encryptData.value = encrypt(data.value, aesKey.value, aesIv.value)
  decryptData.value = decrypt(encryptData.value, aesKey.value, aesIv.value)
}

/**
 * 未实现，自己实现
 */
function sendToSpringBoot() {
  request({
    url: '/test',
    method: 'POST',
    data: {},
  }).then(res => {
    decryptData.value = res.data;
  })
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
  return base64Str.replace(/\+/g, '-').replace(/\//g, '_')
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
  return isUrlSafe.value ? base64ToUrlSafe(result) : result;
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
  data = isUrlSafe.value ? base64ToUrlNotSafe(data) : data
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
</script>

<template>
  <div>
    <button @click="generateAesKeyAndIv">生成 AES key 和 iv</button>

    <p><span>Key：</span>{{ aesKey }}</p>

    <p><span>iv：</span>{{ aesIv }}</p>

    <button @click="convertKeyAndIvToUrlSafe">转换成 url safe</button>

    <p><span>UrlSafeKey：</span>{{ urlSafeKey }}</p>

    <p><span>UrlSafeIv：</span>{{ urlSafeIv }}</p>

    <div style="display: flex; flex-direction: row;height: 50px">
      是否 url safe：
      <input type="radio" :value="true" v-model="isUrlSafe" :checked="isUrlSafe">是
      <input type="radio" :value="false" v-model="isUrlSafe" :checked="!isUrlSafe">否
    </div>

    <input type="text" placeholder="输入要加密的数据" v-model="data" @input="inputChange" />
    <p><span>加密结果：</span>{{encryptData}}</p>
    <p><span>解密结果：</span>{{decryptData}}</p>

    <button @click="sendToSpringBoot">把参数加密发送给spring boot(未实现，自己实现)</button>
    <p><span>json参数明文：</span>{{}}</p>

    <p><span>param参数明文：</span>{{}}</p>

    <p><span>Vue解密spring boot返回密文后：</span>{{decryptResult}}</p>
  </div>
</template>

<style scoped>
button {
  color: cornflowerblue;
  width: 150px;
  height: 50px;
}
span {
  color: red;
}
div {
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  text-align: center;
}
</style>
