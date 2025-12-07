import aiohttp
import asyncio

async def main():
    print(">>> TEST START")

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://api.yookassa.ru/v3/payments",
                timeout=10
            ) as response:
                print(">>> STATUS:", response.status)
                text = await response.text()
                print(">>> BODY:", text[:500])
    except Exception as e:
        print(">>> ERROR:", repr(e))

asyncio.run(main())
