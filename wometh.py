import asyncio
import sys
import httpx
from loguru import logger
from web3 import AsyncWeb3
from eth_account.messages import encode_defunct

g_success, g_fail = 0, 0

logger.remove()
logger.add(sys.stdout, colorize=True, format="<w>{time:HH:mm:ss:SSS}</w> | <r>{extra[fail]}</r>-<g>{extra[success]}</g> | <level>{message}</level>")
logger = logger.patch(lambda record: record["extra"].update(fail=g_fail, success=g_success))


class WomEth:
    def __init__(self, auth_token, privateKey):
        self.http = httpx.AsyncClient(verify=False)
        self.Twitter = httpx.AsyncClient(verify=False)
        self.Twitter.headers = {
            'Accept-Language': 'en-US,en;q=0.8',
            'Authority': 'twitter.com',
            'Origin': 'https://twitter.com',
            'Referer': 'https://twitter.com/',
            'Sec-Ch-Ua': '"Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': "Windows",
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Gpc': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
            'Accept-Encoding': 'gzip, deflate, br',
            'Authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA'
        }
        self.Twitter.cookies.update({'auth_token': auth_token})
        self.w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider('https://rpc.ankr.com/bsc'))
        self.account = self.w3.eth.account.from_key(privateKey)
        self.auth_code, self.token, self.nonce = None, None, None

    async def get_ct0(self):
        try:
            await self.Twitter.get('https://twitter.com/i/api/2/oauth2/authorize')
            self.Twitter.headers.update({'x-csrf-token': self.Twitter.cookies.get('ct0')})
        except Exception as e:
            print(e)

    async def get_auth_code(self):
        try:
            await self.get_ct0()
            params = {
                'code_challenge': 'challenge',
                'code_challenge_method': 'plain',
                'client_id': 'X0RNVE5DeTEzNEdXeUZrSGIweUw6MTpjaQ',
                'redirect_uri': 'https://www.wometh.com',
                'response_type': 'code',
                'scope': 'users.read tweet.read offline.access',
                'state': 'state'
            }
            response = await self.Twitter.get('https://twitter.com/i/api/2/oauth2/authorize', params=params)
            if 'auth_code' in response.text:
                self.auth_code = response.json()['auth_code']
                return True
            logger.error(f'{self.account.address} 获取auth_code失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def twitter_authorize(self):
        try:
            if not await self.get_auth_code():
                return False
            data = {
                'approval': 'true',
                'code': self.auth_code,
            }
            response = await self.Twitter.post('https://twitter.com/i/api/2/oauth2/authorize', data=data)
            if 'redirect_uri' in response.text:
                return True
            logger.error(f'{self.account.address} 推特授权失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def twitter_login(self):
        try:
            if not await self.twitter_authorize():
                return False
            json_data = {
                'code': self.auth_code,
                'redirect_url': 'https://www.wometh.com',
            }
            response = await self.http.post('https://api.wometh.com/api/v1/login', json=json_data)
            if 'token' in response.text:
                self.token = response.json()['data']['token']
                self.http.headers.update({'Authorization': f'Bearer {self.token}'})
                return True
            logger.error(f'{self.account.address} 登录失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def set_wallet(self):
        try:
            response = await self.http.post(f'https://api.wometh.com/api/v1/user/nonce?wallet_address={self.account.address.lower()}')
            if 'true' in response.text:
                nonce = response.json()['data']['nonce']
                signature = self.account.sign_message(encode_defunct(text=nonce))
                json_data = {'wallet_address': self.account.address.lower(), 'sign_data': signature.signature.hex()}
                response = await self.http.post('https://api.wometh.com/api/v1/user/wallet', json=json_data)
                if 'success' in response.text:
                    logger.success(f'{self.account.address} 绑定钱包成功')
                    return True
            logger.error(f'{self.account.address} 设置钱包失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def set_active(self):
        try:
            response = await self.http.put('https://api.wometh.com/api/v1/twitter/active/retweet')
            if 'is_retweet' in response.text:
                logger.success(f'{self.account.address} 激活成功')
                return True
            logger.error(f'{self.account.address} 激活失败')
            return False
        except Exception as e:
            logger.error(e)
            return False


async def main(file_name):
    global g_fail, g_success
    with open(file_name, 'r', encoding='UTF-8') as f, open('wometh_success.txt', 'a') as s, open('wometh_error.txt', 'a') as e:  # eth----privateKey----auth_token
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            lineList = line.split('----')
            WE = WomEth(lineList[1], lineList[2])
            if await WE.twitter_login() and await WE.set_active() and await WE.set_wallet():
                g_success += 1
                logger.success(f'{lineList[0]} 成功')
                s.write(f'{line}----{WE.token}\n')
            else:
                g_fail += 1
                logger.error(f'{lineList[0]} 失败')
                e.write(f'{line}\n')


if __name__ == '__main__':
    _file_name = input('账号文件(eth----privateKey----auth_token一行一个，放txt，拖入): ').strip()
    asyncio.run(main(_file_name))
