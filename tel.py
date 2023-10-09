import requests
from datetime import datetime
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import base64


# 将时间对象格式化为字符串，按照 "yyyyMMddHHmm00" 格式
def get_time():
    # 获取当前时间
    current_time = datetime.now()
    current_time = current_time.replace(second=0)
    formatted_time = current_time.strftime("%Y%m%d%H%M00")
    return formatted_time


# 将手机号码转换为加密后的字符串
def trans_phone(phone_num):
    result = []
    for i in range(11):
        transformed_char = chr((ord(phone_num[i]) + 2) & 0xFFFF)
        result.append(transformed_char)
    return ''.join(result)


# 获取加密后的Base64字符串
def get_encrypted_base64(mobile, password, timestamp):
    try:
        message = "iPhone 14 13.2.3" + mobile + mobile + timestamp + password + "0$$$0."

        public_key_base64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBkLT15ThVgz6/NOl6s8GNPofdWzWbCkWnkaAm7O2LjkM1H7dMvzkiqdxU02jamGRHLX/ZNMCXHnPcW/sDhiFCBN18qFvy8g6VYb9QtroI09e176s+ZCtiv7hbin2cCTj99iUpnEloZm19lwHyo69u5UMiPMpq0/XKBO8lYhN/gwIDAQAB"

        # 解码Base64编码的公钥字符串
        public_key_bytes = base64.b64decode(public_key_base64)
        public_key = RSA.importKey(public_key_bytes)

        # 初始化RSA加密器
        encrypt_cipher = PKCS1_v1_5.new(public_key)

        # 执行加密
        encrypted_bytes = encrypt_cipher.encrypt(message.encode('utf-8'))

        # 将加密结果转换为Base64字符串
        encrypted_base64 = base64.b64encode(encrypted_bytes).decode('utf-8')
        return encrypted_base64
    except Exception as e:
        print(e)
        raise RuntimeError("加密失败")


# 登录获取token
def login(mobile, password):
    data = {
        "headerInfos": {
            "sourcePassword": "Sid98s",
            "clientType": "#9.6.1#channel50#iPhone 14 Pro#",
            "code": "userLoginNormal",
            "userLoginName": mobile,
            "shopId": "20002",
            "source": "110003",
            "timestamp": get_time(),
        },
        "content": {
            "fieldData": {
                "loginType": "4",
                "accountType": "",
                "loginAuthCipherAsymmertric": get_encrypted_base64(mobile, password, get_time()),
                "deviceUid": "3" + mobile,
                "phoneNum": trans_phone(mobile),
                "isChinatelecom": "0",
                "systemVersion": "13.2.3",
                "authentication": password
            },
            "attach": "iPhone"
        }
    }
    s = requests.post('https://appgologin.189.cn:9031/login/client/userLoginNormal', json=data)
    json = s.json()
    if json['responseData']['resultCode'] != '0000':
        raise RuntimeError(json['responseData']['resultDesc'])
    token = json['responseData']['data']['loginSuccessResult']['token']
    return token


# 查询
def query(mobile, token):
    data = {
        "headerInfos": {
            "sourcePassword": "Sid98s",
            "clientType": "#9.6.1#channel50#iPhone X Plus#",
            "code": "userFluxPackage",
            "userLoginName": mobile,
            "shopId": "20002",
            "source": "110003",
            "timestamp": get_time(),
            "token": token
        },
        "content": {
            "fieldData": {
                "provinceCode": "600101",
                "cityCode": "8441900",
                "shopId": "20002",
                "isChinatelecom": "0",
                "account": trans_phone(mobile),
            },
            "attach": "test"
        }
    }
    s = requests.post('https://appfuwu.189.cn:9021/query/qryImportantData', json=data)
    json = s.json()
    if json['responseData']['resultCode'] != '0000':
        raise RuntimeError(json['responseData']['resultDesc'])
    fee_balance = json['responseData']['data']['balanceInfo']['indexBalanceDataInfo']['balance']
    fee_used = json['responseData']['data']['balanceInfo']['phoneBillRegion']['subTitleHh']
    fee_used = fee_used[:-1]
    common_flow_balance = json['responseData']['data']['flowInfo']['commonFlow']['balance']
    common_flow_used = json['responseData']['data']['flowInfo']['commonFlow']['used']
    special_used = json['responseData']['data']['flowInfo']['specialAmount']['used']

    print("话费余额：" + fee_balance + "元")
    print("实时费用：" + fee_used + "元")
    print("通用剩余：" + common_flow_balance + "kb")
    print("通用已用：" + common_flow_used + "kb")
    print("定向已用：" + special_used + "kb")


def main():
    mobile = input("请输入手机号：").strip()
    password = input("请输入密码：").strip()
    query(mobile, login(mobile, password))


if __name__ == "__main__":
    main()
