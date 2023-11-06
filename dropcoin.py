import asyncio
import sys
import httpx
from loguru import logger

g_success, g_fail = 0, 0

logger.remove()
logger.add(sys.stdout, colorize=True, format="<w>{time:HH:mm:ss:SSS}</w> | <r>{extra[fail]}</r>-<g>{extra[success]}</g> | <level>{message}</level>")
logger = logger.patch(lambda record: record["extra"].update(fail=g_fail, success=g_success))


class DropCoin:
    def __init__(self, auth_token, wallet, referral):
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

        }
        self.Twitter.cookies.update({'auth_token': auth_token})
        self.oauth_token, self.authenticity_token, self.oauth_verifier, self.token = None, None, None, None
        self.wallet, self.referral = wallet, referral

    async def get_twitter(self):
        try:
            response = await self.http.post('https://dropcoin.online/auth/twitter')
            if 'oauth_token' in response.text:
                self.oauth_token = response.json()['result']
                self.oauth_token = self.oauth_token.split('=')[-1].strip()
                return True
            logger.error(f'{self.wallet} 获取oauth_token失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def get_twitter_token(self):
        try:
            if not await self.get_twitter():
                return False
            response = await self.Twitter.get(f'https://api.twitter.com/oauth/authorize?oauth_token={self.oauth_token}')
            if 'authenticity_token' in response.text:
                self.authenticity_token = response.text.split('authenticity_token" value="')[1].split('"')[0]
                return True
            logger.error(f'{self.wallet} 获取authenticity_token失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def twitter_authorize(self):
        try:
            if not await self.get_twitter_token():
                return False
            data = {
                'authenticity_token': self.authenticity_token,
                'redirect_after_login': f'https://api.twitter.com/oauth/authorize?oauth_token={self.oauth_token}',
                'oauth_token': self.oauth_token
            }
            response = await self.Twitter.post('https://api.twitter.com/oauth/authorize', data=data)
            if 'oauth_verifier' in response.text:
                self.oauth_verifier = response.text.split('oauth_verifier=')[1].split('"')[0]
                return True
            logger.error(f'{self.wallet} 获取oauth_verifier失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def twitter_login(self):
        try:
            if not await self.twitter_authorize():
                return False
            response = await self.http.get(f'https://dropcoin.online/auth/twitter?oauth_token={self.oauth_token}&oauth_verifier={self.oauth_verifier}')
            if 'token' in response.text:
                self.token = response.json()['token']
                self.http.headers.update({'Authorization': f'Token {self.token}'})
                return True
            logger.error(f'{self.wallet} 登录失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def set_wallet(self):
        try:
            response = await self.http.post('https://dropcoin.online/quests/passing/6', json={'wallet': self.wallet})
            if 'true' in response.text:
                return True
            logger.error(f'{self.wallet} 设置钱包失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def set_referral(self):
        try:
            response = await self.http.post('https://dropcoin.online/quests/passing/11', json={'referral_username': self.referral})
            if 'true' in response.text:
                return True
            logger.error(f'{self.wallet} 设置邀请人失败')
            return False
        except Exception as e:
            logger.error(e)
            return False


async def main(referral_username, file_name):
    global g_fail, g_success
    with open(file_name, 'r') as f, open('dropcoin_success.txt', 'a') as s, open('dropcoin_error.txt', 'a') as e:  # eth----auth_token
        lines = f.readlines()
        for line in lines:
            wallet, auth_token = line.strip().split('----')
            DC = DropCoin(auth_token, wallet, referral_username)
            if await DC.twitter_login() and await DC.set_wallet() and await DC.set_referral():
                g_success += 1
                logger.success(f'{wallet} 成功')
                s.write(f'{wallet}----{auth_token}----{DC.token}\n')
            else:
                g_fail += 1
                logger.error(f'{wallet} 失败')
                e.write(f'{wallet}----{auth_token}\n')


if __name__ == '__main__':
    _referral = input('输入邀请码: ').strip()
    _file_name = input('账号文件(eth----auth_token): ').strip()
    asyncio.run(main(_referral, _file_name))
