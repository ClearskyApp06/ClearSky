# api_test.py

from typing import Any

import aiohttp
import pytest
from quart_rate_limiter import RateLimitExceeded

import apis
import errors
from app import app
from config_helper import logger


@pytest.mark.asyncio
async def test_push():
    api_key = "CLEARSKYtestJIWIR903Jjksrerkoti4"
    push_server = "https://ui.staging.clearsky.app"

    blocked = {
        "as of": "2024-02-25T16:36:27.874102",
        "data": {
            "blocked": [
                {
                    "Handle": "jordanbpeterson.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:aeuetvb7vac3xay76nkphbks",
                    "block_count": 17390,
                    "did": "did:plc:aeuetvb7vac3xay76nkphbks",
                },
                {
                    "Handle": "aify.co",
                    "ProfileURL": "https://bsky.app/profile/did:plc:s3kgjpyoec2fd7ztruqiaxwx",
                    "block_count": 13646,
                    "did": "did:plc:s3kgjpyoec2fd7ztruqiaxwx",
                },
                {
                    "Handle": "endwokeness.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:byet53dwfmr5at7xk56zwmxv",
                    "block_count": 12078,
                    "did": "did:plc:byet53dwfmr5at7xk56zwmxv",
                },
                {
                    "Handle": "shortcovid.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:rjlu6npi554qkz2jcvdt7mc3",
                    "block_count": 9815,
                    "did": "did:plc:rjlu6npi554qkz2jcvdt7mc3",
                },
                {
                    "Handle": "anonymous.expectus.fyi",
                    "ProfileURL": "https://bsky.app/profile/did:plc:xfqcsi7wuwedeqaa5m7aih44",
                    "block_count": 8890,
                    "did": "did:plc:xfqcsi7wuwedeqaa5m7aih44",
                },
                {
                    "Handle": "90sanime.pics",
                    "ProfileURL": "https://bsky.app/profile/did:plc:5krm4pb5gecb5uawvgr7uxuu",
                    "block_count": 8542,
                    "did": "did:plc:5krm4pb5gecb5uawvgr7uxuu",
                },
                {
                    "Handle": "mdbreathe.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:cmo3ypyyvybcgyi2tg2x4sge",
                    "block_count": 8339,
                    "did": "did:plc:cmo3ypyyvybcgyi2tg2x4sge",
                },
                {
                    "Handle": "thedevil.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:k2weqoffrljoi7d45jjhjaqk",
                    "block_count": 7927,
                    "did": "did:plc:k2weqoffrljoi7d45jjhjaqk",
                },
                {
                    "Handle": "catswithaura.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:wwakmfq74pvducx2pbbdxhlg",
                    "block_count": 7521,
                    "did": "did:plc:wwakmfq74pvducx2pbbdxhlg",
                },
                {
                    "Handle": "9gag.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:56eikwlvdd4htq727624spkg",
                    "block_count": 7369,
                    "did": "did:plc:56eikwlvdd4htq727624spkg",
                },
                {
                    "Handle": "afdberlin.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:vzakzcxo3dqgjvlgmqlakcb5",
                    "block_count": 7184,
                    "did": "did:plc:vzakzcxo3dqgjvlgmqlakcb5",
                },
                {
                    "Handle": "womensart1.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:jfpub26kfrtponcqzi7i7udl",
                    "block_count": 6361,
                    "did": "did:plc:jfpub26kfrtponcqzi7i7udl",
                },
                {
                    "Handle": "artificial.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:gr3zsqab63cfvv7nao4mrh7v",
                    "block_count": 6016,
                    "did": "did:plc:gr3zsqab63cfvv7nao4mrh7v",
                },
                {
                    "Handle": "ewerickson.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:2gwoe546lp565vxmzzy2emsl",
                    "block_count": 5993,
                    "did": "did:plc:2gwoe546lp565vxmzzy2emsl",
                },
                {
                    "Handle": "poeticalphotos.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:ha5tvry6kkxiujam6kyjgagg",
                    "block_count": 5871,
                    "did": "did:plc:ha5tvry6kkxiujam6kyjgagg",
                },
                {
                    "Handle": "julianreichelt.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:hwbjiajbxxij27fzdxwgp7h7",
                    "block_count": 5867,
                    "did": "did:plc:hwbjiajbxxij27fzdxwgp7h7",
                },
                {
                    "Handle": "funnyordie.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:m4wkkbc4k5e46hus7zy3tijd",
                    "block_count": 5773,
                    "did": "did:plc:m4wkkbc4k5e46hus7zy3tijd",
                },
                {
                    "Handle": "culture-crit.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:uvsztbhnf2gcplblz5hitxc7",
                    "block_count": 5700,
                    "did": "did:plc:uvsztbhnf2gcplblz5hitxc7",
                },
                {
                    "Handle": "aisky.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:kazwkrel3bvgeqm3wdiydwdf",
                    "block_count": 5615,
                    "did": "did:plc:kazwkrel3bvgeqm3wdiydwdf",
                },
                {
                    "Handle": "othingstodo.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:i6r2cszqypv2qkp5wvppkndo",
                    "block_count": 5601,
                    "did": "did:plc:i6r2cszqypv2qkp5wvppkndo",
                },
            ],
            "blocked_aid": {
                "did:plc:2gwoe546lp565vxmzzy2emsl": "bafkreigkyri2ge24a2gjvbyfqhpv72ean3kqdr5im6e3njdgfcosgtaly4",
                "did:plc:56eikwlvdd4htq727624spkg": "bafkreic2xkbo646nxl44z3zk2zeighlvsgltoqjoolc3ihc26p4sdxityu",
                "did:plc:5krm4pb5gecb5uawvgr7uxuu": "bafkreie6vz5gykxxdf777yiirarw3eyvycbg46to6dknynbxwqrcsl5mfu",
                "did:plc:aeuetvb7vac3xay76nkphbks": "bafkreibnus2odyijekzkiarrthjwwjjaxbqor5ueopfsa3ezk3doyd3t2a",
                "did:plc:byet53dwfmr5at7xk56zwmxv": "bafkreie5wkm74v6kewoeukcla2hdvzfcfsmqvtm5mhnxdvabgjd2fc2jvm",
                "did:plc:cmo3ypyyvybcgyi2tg2x4sge": "bafkreicvorlfinnmygp5ibd65wjvr6tq526fkaksgsrls7v4bw3caluko4",
                "did:plc:gr3zsqab63cfvv7nao4mrh7v": "bafkreias26vb2aujzaktxnnzgkqkydf3unkdu4qd6l765fdvqbt5xe6hma",
                "did:plc:ha5tvry6kkxiujam6kyjgagg": "bafkreigdoleeclxuwukhhqwqsftrofuazhqhvab377v3tyk4jazkvn2ixi",
                "did:plc:hwbjiajbxxij27fzdxwgp7h7": "bafkreidsd5niiokjiqkrgi3ko444rne6t2qhaeyvyhvz7ahjgyyih3xzie",
                "did:plc:i6r2cszqypv2qkp5wvppkndo": "bafkreia6amuooyaq4uk5smuyhks6wqdipso4yjsv46fszxq6zuvkzkjhqy",
                "did:plc:jfpub26kfrtponcqzi7i7udl": "bafkreib35vtob7wsqhye4t3tgkoprye5qeqv4fauedcqomfm3yj6oae52i",
                "did:plc:k2weqoffrljoi7d45jjhjaqk": "bafkreiamm5zsg4fs5gt3qv6ljam57a45ulb2ova5zk2f7sagr4cvowiroq",
                "did:plc:kazwkrel3bvgeqm3wdiydwdf": "bafkreieihktyf7lcy3votcdxkvahtzyyroak34uf42zae4i2be76fnupkm",
                "did:plc:m4wkkbc4k5e46hus7zy3tijd": "bafkreibxjsxyd452tupsqjw252jjnsaqaooyqdhvrdafsu3rhprtcsktfi",
                "did:plc:rjlu6npi554qkz2jcvdt7mc3": "bafkreia7nn5zcs7eftzihvaqhcqd2wge2s4xyel2rebpvtk7p4sjwwae3y",
                "did:plc:s3kgjpyoec2fd7ztruqiaxwx": "bafkreigstp5o3tazxxln47estmi3fvq52wvl3ktnn4bldxnw4mueb5wppa",
                "did:plc:uvsztbhnf2gcplblz5hitxc7": "bafkreieximiueazfy7vqej35sea7477l75tweiipvthjicwqzxz3njy52u",
                "did:plc:vzakzcxo3dqgjvlgmqlakcb5": "bafkreibcalpe4ceeh27wuu42irlkgb3rm6dcxyk3bqcfe7xnjpxxiqojsy",
                "did:plc:wwakmfq74pvducx2pbbdxhlg": "bafkreieeqwlz7l4lk6eztvyfnowockjstvksrqsfveb7hk2rv5rkfuihtm",
                "did:plc:xfqcsi7wuwedeqaa5m7aih44": "bafkreic6auduax3rkmtm6xgaetan5osdm454a4y5wc5ryfcjkg5gnfqhmu",
            },
            "blockers": [
                {
                    "Handle": "godemperorof.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:aaelnwlxvflllswegmearbwo",
                    "block_count": 538414,
                    "did": "did:plc:aaelnwlxvflllswegmearbwo",
                },
                {
                    "Handle": "chiefkeef.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:e4fsmjcj33khuqi6prspceiy",
                    "block_count": 32919,
                    "did": "did:plc:e4fsmjcj33khuqi6prspceiy",
                },
                {
                    "Handle": "joshuajoy.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:vvzu3m7xgl6nldqjbp25pitj",
                    "block_count": 11337,
                    "did": "did:plc:vvzu3m7xgl6nldqjbp25pitj",
                },
                {
                    "Handle": "reishoku.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:yjxotndhnf4jsldpzh3dbbhe",
                    "block_count": 8618,
                    "did": "did:plc:yjxotndhnf4jsldpzh3dbbhe",
                },
                {
                    "Handle": "benclombardo.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:4plzygasgydhuirdrlflqbjo",
                    "block_count": 8353,
                    "did": "did:plc:4plzygasgydhuirdrlflqbjo",
                },
                {
                    "Handle": "populuxe.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:cgxxlxuypmkdqdcpioqny5r6",
                    "block_count": 7787,
                    "did": "did:plc:cgxxlxuypmkdqdcpioqny5r6",
                },
                {
                    "Handle": "thewrittentevs.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:mauk6khnlclkr5k2hnezgmja",
                    "block_count": 5400,
                    "did": "did:plc:mauk6khnlclkr5k2hnezgmja",
                },
                {
                    "Handle": "likeamilkdud.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:d2c3m3xnz4e3x774bq7w43pc",
                    "block_count": 5251,
                    "did": "did:plc:d2c3m3xnz4e3x774bq7w43pc",
                },
                {
                    "Handle": "csam.okconfirmed.com",
                    "ProfileURL": "https://bsky.app/profile/did:plc:o6p7fbjv2xyijweh5uexdeun",
                    "block_count": 4569,
                    "did": "did:plc:o6p7fbjv2xyijweh5uexdeun",
                },
                {
                    "Handle": "fresh-newlook.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:6odst3452scxthx7w3v2tiav",
                    "block_count": 4346,
                    "did": "did:plc:6odst3452scxthx7w3v2tiav",
                },
                {
                    "Handle": "sunsetsnow.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:axrs65zc6hj3m5axp3fth6pw",
                    "block_count": 4263,
                    "did": "did:plc:axrs65zc6hj3m5axp3fth6pw",
                },
                {
                    "Handle": "pupgamer.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:mafslxu4vgugbybjzsuqxdqr",
                    "block_count": 4243,
                    "did": "did:plc:mafslxu4vgugbybjzsuqxdqr",
                },
                {
                    "Handle": "itwont.run",
                    "ProfileURL": "https://bsky.app/profile/did:plc:nyykk5p7laar725gdnypopsh",
                    "block_count": 4160,
                    "did": "did:plc:nyykk5p7laar725gdnypopsh",
                },
                {
                    "Handle": "sunagimochan.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:lsoslz2tnl5rudrd7toaxly3",
                    "block_count": 3554,
                    "did": "did:plc:lsoslz2tnl5rudrd7toaxly3",
                },
                {
                    "Handle": "hamandegger.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:wgiw4zvjhfhhubf6dtocjern",
                    "block_count": 3462,
                    "did": "did:plc:wgiw4zvjhfhhubf6dtocjern",
                },
                {
                    "Handle": "blueotter.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:yq6oqday6xtoqcgigdotnglw",
                    "block_count": 3376,
                    "did": "did:plc:yq6oqday6xtoqcgigdotnglw",
                },
                {
                    "Handle": "palomar.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:2col443nxnlr3qxmlh53u2oi",
                    "block_count": 3321,
                    "did": "did:plc:2col443nxnlr3qxmlh53u2oi",
                },
                {
                    "Handle": "nanamiasari.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:ptlddkaqekq5xj4icqh3btu3",
                    "block_count": 3320,
                    "did": "did:plc:ptlddkaqekq5xj4icqh3btu3",
                },
                {
                    "Handle": "elaxor.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:ofca62ov5uoae3j772j5vxkx",
                    "block_count": 3210,
                    "did": "did:plc:ofca62ov5uoae3j772j5vxkx",
                },
                {
                    "Handle": "john88.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:nhfzuw3qpspigcbhopyjyoxg",
                    "block_count": 2987,
                    "did": "did:plc:nhfzuw3qpspigcbhopyjyoxg",
                },
            ],
            "blockers_aid": {
                "did:plc:2col443nxnlr3qxmlh53u2oi": "",
                "did:plc:4plzygasgydhuirdrlflqbjo": "bafkreidmvofs6nmkoqadp4vkvh26jzh73bzvf5s2ajvt5ztnkqxneyayvq",
                "did:plc:6odst3452scxthx7w3v2tiav": "bafkreid4znwozgnn5vz7jhk5wsub73dkwnqf3hu4cs7u5njewqiixugi4q",
                "did:plc:aaelnwlxvflllswegmearbwo": "bafkreicekc6sdf7i5aibzo6yhmuvykwj43gruxmyc5wsmgkahflswwez6a",
                "did:plc:axrs65zc6hj3m5axp3fth6pw": "bafkreicqwvuqqhzi6vzexyi7c5arfov4cqr26hkxggameqmd3nkldovud4",
                "did:plc:cgxxlxuypmkdqdcpioqny5r6": "bafkreiaaaksgtbfk7wvuwrzgyrssvfqm7gzxmilsf6w4jz33eiz6auwyo4",
                "did:plc:d2c3m3xnz4e3x774bq7w43pc": "bafkreig672aogrqgj6hj3fhilgetxrfty4pf3vv2q25sjzm4uicnvs3wru",
                "did:plc:e4fsmjcj33khuqi6prspceiy": "bafkreifykraakgmpblk7q574amv23yffetp43fmxubja4vnhu74rob3ida",
                "did:plc:lsoslz2tnl5rudrd7toaxly3": "bafkreicqe2lokrhlmxi2zvygqeq2wycap6fsfq3ljy5l7n36kxggyzghee",
                "did:plc:mafslxu4vgugbybjzsuqxdqr": "bafkreicmimmf727toysnirqlrngcr3dtdcqq76dklzdqhsz7gkaz6enpli",
                "did:plc:mauk6khnlclkr5k2hnezgmja": "bafkreigbmijkhof4qsutjttodry4h33euthlu6xcvezzxlie2aejuhteaq",
                "did:plc:nhfzuw3qpspigcbhopyjyoxg": "",
                "did:plc:nyykk5p7laar725gdnypopsh": "bafkreidao55d575zbvdekot3zvtqq63lj4ebdj2ydodjy4n7o4vr3dkstm",
                "did:plc:o6p7fbjv2xyijweh5uexdeun": "bafkreiepeuh6mz4pc2mzmjyysizxz47zcm454tednxk5ntrmu5miuvjgr4",
                "did:plc:ofca62ov5uoae3j772j5vxkx": "bafkreiezuxscejajajbivlygsbfmeqkbquwugp7hltxcetcbzyjydhjroe",
                "did:plc:ptlddkaqekq5xj4icqh3btu3": "bafkreidrkrwvnj5kvnyyhgmbvcqrytwjuxh2kcogfhv7ipnj6qjqpbicdu",
                "did:plc:vvzu3m7xgl6nldqjbp25pitj": "bafkreifjxjfheaynu5cvf4zxqkw3jhr5urwkqykklq64bggdghhmeddfji",
                "did:plc:wgiw4zvjhfhhubf6dtocjern": "bafkreibkkfry5co2opt3itgcx3y2dkuqwpy3kzwkmf5b6b7q6i76qutduu",
                "did:plc:yjxotndhnf4jsldpzh3dbbhe": "bafkreifomfskzqebqe2h7as2m2e3g6tmnmzintulxgw7gdvvdmhesdbq4u",
                "did:plc:yq6oqday6xtoqcgigdotnglw": "bafkreif7yd74dsurrjboyvrqwmwdbhpqs3w4eku36gmcw2vfqk4vncrnyq",
            },
        },
    }
    blocked_24 = {
        "as of": "2024-02-25T16:37:24.179892",
        "data": {
            "blocked24": [
                {
                    "Handle": "aobeko.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:tsvn6c6expncr2k46aldhpsi",
                    "block_count": 503,
                    "did": "did:plc:tsvn6c6expncr2k46aldhpsi",
                },
                {
                    "Handle": "drewtoothpaste.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:baz3nw2zdnyfllf2prg76ukv",
                    "block_count": 460,
                    "did": "did:plc:baz3nw2zdnyfllf2prg76ukv",
                },
                {
                    "Handle": "uruzrune.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:xrrj5gmohj35n5crykhiz7vc",
                    "block_count": 394,
                    "did": "did:plc:xrrj5gmohj35n5crykhiz7vc",
                },
                {
                    "Handle": "taylorlorenz.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:wo3lxbcfvdptzxyvq3qt2rgj",
                    "block_count": 371,
                    "did": "did:plc:wo3lxbcfvdptzxyvq3qt2rgj",
                },
                {
                    "Handle": "mubumito1970.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:txg2gjnrhregqpx6tdk6fthq",
                    "block_count": 339,
                    "did": "did:plc:txg2gjnrhregqpx6tdk6fthq",
                },
                {
                    "Handle": "arasen1971.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:mbisijoprrvmjauqpdnzqsbu",
                    "block_count": 322,
                    "did": "did:plc:mbisijoprrvmjauqpdnzqsbu",
                },
                {
                    "Handle": "hesageru1971.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:trzmsbjn6a5pmcpfyff3ydi5",
                    "block_count": 287,
                    "did": "did:plc:trzmsbjn6a5pmcpfyff3ydi5",
                },
                {
                    "Handle": "peimon1981.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:ijq33pkxqlohaxffklfrdazv",
                    "block_count": 279,
                    "did": "did:plc:ijq33pkxqlohaxffklfrdazv",
                },
                {
                    "Handle": "belmontexcorcist.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:pkbynldeka42ktbailqjfyua",
                    "block_count": 275,
                    "did": "did:plc:pkbynldeka42ktbailqjfyua",
                },
                {
                    "Handle": "dasharez0ne.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:sxxnhzipsapdm5inx44fr322",
                    "block_count": 272,
                    "did": "did:plc:sxxnhzipsapdm5inx44fr322",
                },
                {
                    "Handle": "nauru-japan.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:6l2o4gzmjznc6cydsbucbmj5",
                    "block_count": 264,
                    "did": "did:plc:6l2o4gzmjznc6cydsbucbmj5",
                },
                {
                    "Handle": "taitai1976.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:7nljtjenwuzmfbviiyp6iywn",
                    "block_count": 255,
                    "did": "did:plc:7nljtjenwuzmfbviiyp6iywn",
                },
                {
                    "Handle": "vailalamadness.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:by7tbosrzfzztcgryxwo3els",
                    "block_count": 240,
                    "did": "did:plc:by7tbosrzfzztcgryxwo3els",
                },
                {
                    "Handle": "emilywilliams012.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:sisswuewdgila5zuwauyvaui",
                    "block_count": 230,
                    "did": "did:plc:sisswuewdgila5zuwauyvaui",
                },
                {
                    "Handle": "yaminbismillah.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:5e4xasverrm7hiy3mfnvnc4d",
                    "block_count": 213,
                    "did": "did:plc:5e4xasverrm7hiy3mfnvnc4d",
                },
                {
                    "Handle": "cookcook22.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:mgt26lp2gcpzauhs4fds7oji",
                    "block_count": 194,
                    "did": "did:plc:mgt26lp2gcpzauhs4fds7oji",
                },
                {
                    "Handle": "elizabeth010.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:zdcuqf474b6pzqgcd4645asn",
                    "block_count": 188,
                    "did": "did:plc:zdcuqf474b6pzqgcd4645asn",
                },
                {
                    "Handle": "freekae.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:uojd43utfwd2afhuw47m7jjx",
                    "block_count": 186,
                    "did": "did:plc:uojd43utfwd2afhuw47m7jjx",
                },
                {
                    "Handle": "btcbreakdown.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:xufmktwgylcyqth7yeoihm2l",
                    "block_count": 184,
                    "did": "did:plc:xufmktwgylcyqth7yeoihm2l",
                },
                {
                    "Handle": "anonimoromano.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:znn5ktv5zi66n2asrwlrvhcv",
                    "block_count": 179,
                    "did": "did:plc:znn5ktv5zi66n2asrwlrvhcv",
                },
            ],
            "blocked_aid": {
                "did:plc:5e4xasverrm7hiy3mfnvnc4d": "bafkreihhqqsrp2rqddb2qdpglcco6vjfei2kdbb7gjcrhm7pglzo7lc7ca",
                "did:plc:6l2o4gzmjznc6cydsbucbmj5": "bafkreibukw26txe5xxwwxakqah5iypqevei6s67lb2273ylwpquesmurc4",
                "did:plc:7nljtjenwuzmfbviiyp6iywn": "bafkreidomnzpz3qo24b2kge3bb6xeghyut62uasdljawnhm4fgpomffrgm",
                "did:plc:baz3nw2zdnyfllf2prg76ukv": "bafkreif2exuo3ymgkkazbdgzdddugfr34sv6bazbq2ykv7yc67wqxk72fu",
                "did:plc:by7tbosrzfzztcgryxwo3els": "bafkreieteud3uts7tsff7mva6hyzlkvrquhartoz3d4wp2slvurt5wasda",
                "did:plc:ijq33pkxqlohaxffklfrdazv": "bafkreiguw4wprsf2l4i7ebkpo3zhbf7twik5t52zm6bpprg7fazazromvu",
                "did:plc:mbisijoprrvmjauqpdnzqsbu": "bafkreiftx7wxn543mc6cuvfajju5mkys45f7oqilq4nwxeb5nf7igyjwli",
                "did:plc:mgt26lp2gcpzauhs4fds7oji": "bafkreidnvztwy637xwkxso7io7utjv7opl73ifaqhyerk4kwmbaba6z4ii",
                "did:plc:pkbynldeka42ktbailqjfyua": "bafkreic3xhyqkw5q4d7cym4z6m23sgs6xioi6vjrlebpnsere34asikihu",
                "did:plc:sisswuewdgila5zuwauyvaui": "bafkreiayflbak5wi7kmhqbva3kbprtin5bpv4w3zvvpk6mugmx43akivke",
                "did:plc:sxxnhzipsapdm5inx44fr322": "bafkreigr57rxrn5iqawjnj5kfu3ueytuwvs2jp6yo5tua6ucn3wd3yasly",
                "did:plc:trzmsbjn6a5pmcpfyff3ydi5": "bafkreicdcyrmfgpjgvcnlmek5vb5ibkzgyhy5tj7umwbmbjyicp6e6ezae",
                "did:plc:tsvn6c6expncr2k46aldhpsi": "bafkreig6hxxjqmwomf33ndq2x3jwpke776tzd5jaau4n5pwjtnthmj7a2q",
                "did:plc:txg2gjnrhregqpx6tdk6fthq": "bafkreiawzhvlom6g7l2cmtrccu5s4eeutzoc26gttf2cakuvmgl5fsx7xm",
                "did:plc:uojd43utfwd2afhuw47m7jjx": "bafkreidr5soocf5rpsycylpiq7zt4xbpoeudolwnhoc2adof3feqgz4zxe",
                "did:plc:wo3lxbcfvdptzxyvq3qt2rgj": "bafkreicwwe5tldfztlhmt3ptek4caneerpzovsendty5nf4v4oqqnyxdly",
                "did:plc:xrrj5gmohj35n5crykhiz7vc": "bafkreihfb7i3m2h4q7x2lzwwj2gxoy6tcgczfy5jpa5dpii4swlmbdmh5u",
                "did:plc:xufmktwgylcyqth7yeoihm2l": "bafkreif266lmdtkmvnpakgbeicsgjwcbar2lhjlwt5zf4lxh3tvtkaurza",
                "did:plc:zdcuqf474b6pzqgcd4645asn": "bafkreidbswerb2k56wjzednqcuelpk5nbjbtd2o3a7jdmpyw7hxajzy5fe",
                "did:plc:znn5ktv5zi66n2asrwlrvhcv": "bafkreiau45vqe7b5k3serwdn6s6lblmmio7tlphmez2nifrl3fdfn56mym",
            },
            "blockers24": [
                {
                    "Handle": "godemperorof.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:aaelnwlxvflllswegmearbwo",
                    "block_count": 23332,
                    "did": "did:plc:aaelnwlxvflllswegmearbwo",
                },
                {
                    "Handle": "myasugi.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:635k5gu52v6kxeskapusmq4n",
                    "block_count": 1195,
                    "did": "did:plc:635k5gu52v6kxeskapusmq4n",
                },
                {
                    "Handle": "whydoilikethis.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:g2xshwj4o33b5wzxs3xspfxk",
                    "block_count": 968,
                    "did": "did:plc:g2xshwj4o33b5wzxs3xspfxk",
                },
                {
                    "Handle": "peakpilot.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:d2k2r7dfatmxuy3km2e36fn7",
                    "block_count": 851,
                    "did": "did:plc:d2k2r7dfatmxuy3km2e36fn7",
                },
                {
                    "Handle": "fresh-newlook.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:6odst3452scxthx7w3v2tiav",
                    "block_count": 813,
                    "did": "did:plc:6odst3452scxthx7w3v2tiav",
                },
                {
                    "Handle": "konokono7.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:mkr2mvboohuwnrpsp6uh6xfx",
                    "block_count": 632,
                    "did": "did:plc:mkr2mvboohuwnrpsp6uh6xfx",
                },
                {
                    "Handle": "nanamiasari.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:ptlddkaqekq5xj4icqh3btu3",
                    "block_count": 581,
                    "did": "did:plc:ptlddkaqekq5xj4icqh3btu3",
                },
                {
                    "Handle": "nagarage.dev",
                    "ProfileURL": "https://bsky.app/profile/did:plc:g3ytqjxk2rqfb5jrda7nj556",
                    "block_count": 568,
                    "did": "did:plc:g3ytqjxk2rqfb5jrda7nj556",
                },
                {
                    "Handle": "saltydogfella.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:vig5txmvxugry3h5x36mcva2",
                    "block_count": 492,
                    "did": "did:plc:vig5txmvxugry3h5x36mcva2",
                },
                {
                    "Handle": "sunagimochan.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:lsoslz2tnl5rudrd7toaxly3",
                    "block_count": 418,
                    "did": "did:plc:lsoslz2tnl5rudrd7toaxly3",
                },
                {
                    "Handle": "nero-bs-nero.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:2a33okh2b4bt33dbte55yobb",
                    "block_count": 414,
                    "did": "did:plc:2a33okh2b4bt33dbte55yobb",
                },
                {
                    "Handle": "christl.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:kfvqwkstbuelqxaayr4k6kul",
                    "block_count": 413,
                    "did": "did:plc:kfvqwkstbuelqxaayr4k6kul",
                },
                {
                    "Handle": "snappleitalist.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:hieur2sqkltuwxefye7vl76w",
                    "block_count": 395,
                    "did": "did:plc:hieur2sqkltuwxefye7vl76w",
                },
                {
                    "Handle": "unoasterisk.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:cnskju6afshpkuavdm65d3rw",
                    "block_count": 390,
                    "did": "did:plc:cnskju6afshpkuavdm65d3rw",
                },
                {
                    "Handle": "barrkat.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:6tah4r2v6aoy5uhlfswqdjdo",
                    "block_count": 388,
                    "did": "did:plc:6tah4r2v6aoy5uhlfswqdjdo",
                },
                {
                    "Handle": "berrak.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:ucdxsz454wtdp3unyq4kny6s",
                    "block_count": 360,
                    "did": "did:plc:ucdxsz454wtdp3unyq4kny6s",
                },
                {
                    "Handle": "14th-division.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:3cd3jkngfnmumtyrbttd4lme",
                    "block_count": 327,
                    "did": "did:plc:3cd3jkngfnmumtyrbttd4lme",
                },
                {
                    "Handle": "thoriac.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:mdinafwn6pvegvzngpx5schs",
                    "block_count": 308,
                    "did": "did:plc:mdinafwn6pvegvzngpx5schs",
                },
                {
                    "Handle": "sayuhome.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:7svuhadlixx7e6tucn3vcehr",
                    "block_count": 303,
                    "did": "did:plc:7svuhadlixx7e6tucn3vcehr",
                },
                {
                    "Handle": "xdretrogaming.bsky.social",
                    "ProfileURL": "https://bsky.app/profile/did:plc:fnofha5jlcwh33htovb446bu",
                    "block_count": 281,
                    "did": "did:plc:fnofha5jlcwh33htovb446bu",
                },
            ],
            "blockers_aid": {
                "did:plc:2a33okh2b4bt33dbte55yobb": "bafkreicr373iyzgqrqjj2ezvgt376wyzcuquttq2bx6ukvexq5jkdcp3mm",
                "did:plc:3cd3jkngfnmumtyrbttd4lme": "bafkreia53qevgmzy6cbx6wupiria4npex5nnzio75djogesyppd5vk2gam",
                "did:plc:635k5gu52v6kxeskapusmq4n": "bafkreifpvrcsllfnetasndfg3lga3skay3kafdsphlrsd2zy4r5bxqrb7m",
                "did:plc:6odst3452scxthx7w3v2tiav": "bafkreid4znwozgnn5vz7jhk5wsub73dkwnqf3hu4cs7u5njewqiixugi4q",
                "did:plc:6tah4r2v6aoy5uhlfswqdjdo": "bafkreidondvujg4w5qg6b4chtgidrc2tdlgaehcgnmqxfm3dv2utai32qq",
                "did:plc:7svuhadlixx7e6tucn3vcehr": "bafkreigmdhckua3bmr3a7l2z7wa72qua6vrttel3ht6knidp3uolnc4cfq",
                "did:plc:aaelnwlxvflllswegmearbwo": "bafkreicekc6sdf7i5aibzo6yhmuvykwj43gruxmyc5wsmgkahflswwez6a",
                "did:plc:cnskju6afshpkuavdm65d3rw": "bafkreicegz3qtqlbd22ppre7im6yxsvscvhxvurc4by7fcujhzu47qvxum",
                "did:plc:d2k2r7dfatmxuy3km2e36fn7": "bafkreib62qbik7yyncw3253r5yj4ywfnjma5epv2h47vbgkfdthza7b3oy",
                "did:plc:fnofha5jlcwh33htovb446bu": "bafkreigsco655wp2wln3y66v63sqgccwyqcldzbht7ggncjv5jjmiv3ojm",
                "did:plc:g2xshwj4o33b5wzxs3xspfxk": "bafkreiabzguv3uvpth3a3w2fvgwhvl7qzmvcqn63sodk4ds5lp5v3g2y34",
                "did:plc:g3ytqjxk2rqfb5jrda7nj556": "bafkreifqewbyfq6m74zcd4eersvqqnrs7nmkq5icfpe6xlyyfvu2l4acje",
                "did:plc:hieur2sqkltuwxefye7vl76w": "bafkreiggmrna5vawvvqsceeycvlkettpgozliqp5giu52tfpusbnj7nuxm",
                "did:plc:kfvqwkstbuelqxaayr4k6kul": "bafkreicnx23vybu4b3x7bj7zttab62bs6d4x2ea4yhxmdmhzyv3exkrncm",
                "did:plc:lsoslz2tnl5rudrd7toaxly3": "bafkreicqe2lokrhlmxi2zvygqeq2wycap6fsfq3ljy5l7n36kxggyzghee",
                "did:plc:mdinafwn6pvegvzngpx5schs": "bafkreihmfzq3qu2h5fcn5zjbn3gkjoem4hfcfkymkln3wbf7cwawpvhmjq",
                "did:plc:mkr2mvboohuwnrpsp6uh6xfx": "bafkreiec2lcdqcv5ph55nxna6vtkjtorx2lxqdsnczkrwye5zds56i6oky",
                "did:plc:ptlddkaqekq5xj4icqh3btu3": "bafkreidrkrwvnj5kvnyyhgmbvcqrytwjuxh2kcogfhv7ipnj6qjqpbicdu",
                "did:plc:ucdxsz454wtdp3unyq4kny6s": "bafkreibk2rltmavzgfvvnyrybsad7o76o2pgryldaop4l36peoaejxprfm",
                "did:plc:vig5txmvxugry3h5x36mcva2": "bafkreieewdiwhtt4igj6ql7sge4jy72acc6zdupzvr6fyhzuh7pgkdnv24",
            },
        },
    }
    block_stats = {
        "as of": "2024-02-25T16:45:57.819942",
        "data": {
            "averageNumberOfBlocked": {"displayname": "Average Number of Users Blocked", "value": 5.29},
            "averageNumberOfBlocks": {"displayname": "Average Number of Blocks", "value": "12.83"},
            "numberBlock1": {"displayname": "Number of Users Blocking 1 User", "value": "188,270"},
            "numberBlocked1": {"displayname": "Number of Users Blocked by 1 User", "value": "603,014"},
            "numberBlocked101and1000": {"displayname": "Number of Users Blocked by 101-1000 Users", "value": "5,553"},
            "numberBlocked2and100": {"displayname": "Number of Users Blocked by 2-100 Users", "value": "450,793"},
            "numberBlockedGreaterThan1000": {
                "displayname": "Number of Users Blocked by More than 1000 Users",
                "value": "525",
            },
            "numberBlocking101and1000": {"displayname": "Number of Users Blocking 101-1000 Users", "value": "9,224"},
            "numberBlocking2and100": {"displayname": "Number of Users Blocking 2-100 Users", "value": "239,373"},
            "numberBlockingGreaterThan1000": {
                "displayname": "Number of Users Blocking More than 1000 Users",
                "value": "124",
            },
            "numberOfTotalBlocks": {"displayname": "Number of Total Blocks", "value": "5,607,036"},
            "numberOfUniqueUsersBlocked": {"displayname": "Number of Unique Users Blocked", "value": "1,059,885"},
            "numberOfUniqueUsersBlocking": {"displayname": "Number of Unique Users Blocking", "value": "436,991"},
            "percentNumberBlocked1": {"displayname": "Percent of Users Blocked by 1 User", "value": 56.89},
            "percentNumberBlocked101and1000": {
                "displayname": "Percent of Users Blocked by 101-1000 Users",
                "value": 0.52,
            },
            "percentNumberBlocked2and100": {"displayname": "Percent of Users Blocked by 2-100 Users", "value": 42.53},
            "percentNumberBlockedGreaterThan1000": {
                "displayname": "Percent of Users Blocked by More than 1000 Users",
                "value": 0.05,
            },
            "percentNumberBlocking1": {"displayname": "Percent of Users Blocking 1 User", "value": 43.08},
            "percentNumberBlocking101and1000": {
                "displayname": "Percent of Users Blocking 101-1000 Users",
                "value": 2.11,
            },
            "percentNumberBlocking2and100": {"displayname": "Percent of Users Blocking 2-100 Users", "value": 54.78},
            "percentNumberBlockingGreaterThan1000": {
                "displayname": "Percent of Users Blocking More than 1000 Users",
                "value": 0.03,
            },
            "percentUsersBlocked": {"displayname": "Percent Users Blocked", "value": 19.63},
            "percentUsersBlocking": {"displayname": "Percent Users Blocking", "value": 8.09},
            "totalUsers": {"displayname": "Total Users", "value": "5,399,765"},
        },
    }
    total_users = {
        "data": {
            "active_count": {"displayname": "Active Users", "value": "5,041,644"},
            "deleted_count": {"displayname": "Deleted Users", "value": "358,123"},
            "total_count": {"displayname": "Total Users", "value": "5,399,765"},
        }
    }

    push_data = [blocked, blocked_24, block_stats, total_users]
    if api_key:
        try:
            send_api = {
                "top_blocked": f"{push_server}/api/v1/base/reporting/stats-cache/top-blocked",
                "top_24_blocked": f"{push_server}/api/v1/base/reporting/stats-cache/top-24-blocked",
                "block_stats": f"{push_server}/api/v1/base/reporting/stats-cache/block-stats",
                "total_users": f"{push_server}/api/v1/base/reporting/stats-cache/total-users",
            }
            headers = {"X-API-Key": f"{api_key}"}
            async with aiohttp.ClientSession(headers=headers) as session:
                for data, api in zip(push_data, send_api.values(), strict=False):
                    async with session.post(api, json=data) as response:
                        if response.status == 200:
                            logger.info(f"Data successfully pushed to {send_api}")
                        else:
                            logger.error("Failed to push data to the destination server")
                            continue
        except Exception as e:
            logger.error(f"An error occurred: {e}")
    else:
        logger.error("PUSH not executed, no API key configured.")


@pytest.mark.asyncio
async def test_auth_api_v1():
    # api_key = "CLEARSKYtestd121ascmkdneaorSDno32"
    api_key = "CLEARSKYprodtest67890asdfghjklqw"
    test_client = app.test_client()

    # api_endpoint = "https://staging.bsky.thieflord.dev/api/v1/base/internal/status/process-status"
    # api_endpoint = "http://localhost/api/v1/base/internal/status/process-status"
    # api_endpoint = "http://staging.bsky.thieflord.dev/api/v1/blocklist-search-blocking/test.tennis.thieflord.dev"
    # api_endpoint = "http://localhost/api/v1/lists/block-stats"
    # api_endpoint = "http://api.staging.clearsky.services/api/v1/anon/lists/fun-facts"
    # api_endpoint = "https://staging.bsky.thieflord.dev/api/v1/blocklist-search-blocking/test.tennis.thieflord.dev/alechiaval.bsky.social"
    # api_endpoint = "https://staging.bsky.thieflord.dev/api/v1/lists/block-stats"
    # api_endpoint = "https://staging.bsky.thieflord.dev/api/v1/blocklist/boykisser.expert"
    # api_endpoint = "https://staging.bsky.thieflord.dev/api/v1/single-blocklist/thieflord.dev"
    # api_endpoint = "https://staging.bsky.thieflord.dev/api/v1/total-users"
    # api_endpoint = "https://staging.bsky.thieflord.dev/api/v1/get-did/thieflord.dev"
    # api_endpoint = "https://staging.bsky.thieflord.dev/api/v1/get-handle/thieflford.dev"
    # api_endpoint = "https://api.staging.clearsky.services/api/v1/get-handle-history/thieflord.dev"
    # api_endpoint = "https://staging.bsky.thieflord.dev/api/v1/blocklist-search-blocking/desir.ee/thieflord.dev"
    # api_endpoint = "https://staging.bsky.thieflord.dev/api/v1/in-common-blocklist/"
    # api_endpoint = "http://localhost/api/v1/blocklist-search-blocking/desir.ee/thieflord.dev"
    # api_endpoint = "http://localhost/api/v1/blocklist-search-blocked/thieflord.dev/desir.ee"
    # api_endpoint = "https://staging.bsky.thieflord.dev/api/v1/total-users"
    # api_endpoint = "http://localhost/api/v1/single-blocklist/thieflord.dev"
    # api_endpoint = "http://localhost/api/v1/at-uri/at://did:plc:smcanwhzsj5dqp4yew7y6ybx/app.bsky.graph.listblock/3kf2kfcic5od2u"
    # api_endpoint = "http://localhost/api/v1/get-moderation-list/gaminsdfvf"
    # api_endpoint = "http://localhost/api/v1/auth/blocklist/rudyfraser.com"
    # api_endpoint = "http://localhost/api/v1/auth/base/internal/api-check?key_type="
    # api_endpoint = "http://localhost/api/v1/base/internal/status/process-status"
    api_endpoint = "/api/v1/base/internal/status/process-status"

    # Define the headers with the API key
    headers = {"X-API-Key": f"{api_key}"}

    # Send an OPTIONS request to the API endpoint with the headers
    options_response = await test_client.options(api_endpoint, headers=headers)

    for key, value in options_response.headers.items():
        logger.info(f"Header: {key} = {value}")

    # Send a GET request to the API endpoint with the headers
    response = await test_client.get(api_endpoint, headers=headers)

    # Print the response headers
    for key, value in response.headers.items():
        logger.info(f"Header: {key} = {value}")

    # Check if the 'Access-Control-Allow-Origin' header is present
    if "Access-Control-Allow-Origin" in response.headers:
        # Print the allowed origin(s)
        logger.info(f"Access-Control-Allow-Origin: {response.headers['Access-Control-Allow-Origin']}")

        # Check if it allows the origin of your request
        if response.headers["Access-Control-Allow-Origin"] == "*":
            logger.info("CORS is configured to allow all origins.")
        else:
            logger.info("CORS is configured to allow specific origins.")
    else:
        logger.info("Access-Control-Allow-Origin header not found. CORS might not be configured.")

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        # Print the response content
        logger.info(response.text)
    else:
        logger.info(f"Request failed with status code {response.status_code}")


@pytest.mark.asyncio
async def test_anon_api_v1():
    test_client = app.test_client()
    # api_endpoint = "https://staging.bsky.thieflord.dev/api/v1/base/internal/status/process-status"
    # api_endpoint = "https://api.clearsky.services/api/v1/anon/base/internal/status/process-status"
    # api_endpoint = "http://staging.bsky.thieflord.dev/api/v1/blocklist-search-blocking/test.tennis.thieflord.dev"
    # api_endpoint = "http://localhost/api/v1/lists/block-stats"
    # api_endpoint = "https://api.staging.clearsky.services/api/v1/anon/lists/fun-facts"
    # api_endpoint = "https://staging.bsky.thieflord.dev/api/v1/blocklist-search-blocking/test.tennis.thieflord.dev/alechiaval.bsky.social"
    # api_endpoint = "https://staging.bsky.thieflord.dev/api/v1/lists/block-stats"
    # api_endpoint = "http://localhost/api/v1/anon/blocklist/did:plc:g6siaz6zgxndohrxdeg6a2bd"
    # api_endpoint = "https://api.staging.clearsky.services/api/v1/anon/single-blocklist/did:plc:yk4dd2qkboz2yv6tpubpc6co"
    # api_endpoint = "https://api.clearsky.services/api/v1/anon/single-blocklist/mapconsuela.bsky.social"
    # api_endpoint = "https://staging.bsky.thieflord.dev/api/v1/anon/total-users"
    # api_endpoint = "https://staging.bsky.thieflord.dev/api/v1/get-did/thieflord.dev"
    # api_endpoint = "https://api.clearsky.services/api/v1/anon/get-handle/thieflord.dev"
    # api_endpoint = "https://api.staging.clearsky.services/api/v1/anon/get-handle-history/genco.me"
    # api_endpoint = "https://staging.bsky.thieflord.dev/api/v1/blocklist-search-blocking/desir.ee/thieflord.dev"
    # api_endpoint = "https://staging.bsky.thieflord.dev/api/v1/in-common-blocklist/"
    # api_endpoint = "http://localhost/api/v1/blocklist-search-blocking/desir.ee/thieflord.dev"
    # api_endpoint = "http://localhost/api/v1/anon/blocklist-search-blocked/thieflord.dev/desir.ee"
    # api_endpoint = "https://staging.bsky.thieflord.dev/api/v1/total-users"
    # api_endpoint = "http://localhost/api/v1/anon/single-blocklist/thieflord.dev"
    api_endpoint = "/api/v1/anon/single-blocklist/dollyeldritch.bsky.social"
    # api_endpoint = "http://localhost/api/v1/anon/blocklist/thieflord.dev"
    # api_endpoint = "http://localhost/api/v1/at-uri/at://did:plc:smcanwhzsj5dqp4yew7y6ybx/app.bsky.graph.listblock/3kf2kfcic5od2u"
    # api_endpoint = "http://localhost/api/v1/get-moderation-list/gaminsdfvf"
    # api_endpoint = "http://localhost/api/v1/anon/blocklist/kinewtesting2.bsky.social"
    # api_endpoint = "https://api.clearsky.services/api/v1/anon/blocklist/kinewtesting2.bsky.social"
    # api_endpoint = "http://localhost/api/v1/anon/lists/dids-per-pds"
    # api_endpoint = "http://localhost/api/v1/anon/subscribe-blocks-blocklist/smolbeansprout.bsky.social"
    # api_endpoint = "http://localhost/api/v1/anon/subscribe-blocks-single-blocklist/krkr2019.bsky.social"
    # api_endpoint = "http://localhost/api/v1/anon/subscribe-blocks-blocklist/did:plc:gi33pbqny4kxmhz2da3gxkax"
    # api_endpoint = "https://api.clearsky.services/api/v1/anon/total-users"
    # api_endpoint = "https://api.clearsky.services/api/v1/anon/lists/fun-facts"
    # api_endpoint = "https://api.clearsky.services/api/v1/anon/lists/funer-facts"
    # api_endpoint = "https://api.clearsky.services/api/v1/anon/lists/block-stats"
    # api_endpoint = "https://api.clearsky.services/api/v1/anon/base/autocomplete/thi"
    # api_endpoint = "https://api.clearsky.services/api/v1/anon/at-uri/at://did:plc:synka4gchwjmophklcsndndf/app.bsky.feed.post/3klnptzxy3b2f"
    # api_endpoint = "https://api.staging.clearsky.services/api/v1/anon/data-transaction/query"
    # api_endpoint = "https://api.clearsky.services/api/v1/anon/validation/validate-handle/drbonnieanderson.bsky.social"
    # api_endpoint = "https://clearsky.app/api/v1/base/internal/status/process-status"
    # api_endpoint = "https://api.clearsky.services/api/v1/anon/total-users"
    # api_endpoint = "https://api.clearsky.services/api/v1/anon/lists/fun-facts"
    # api_endpoint = "https://api.clearsky.services/api/v1/anon/cursor-recall/status"
    # api_endpoint = "https://api.clearsky.services/api/v1/anon/status/time-behind"

    logger.info(f"API endpoint: {api_endpoint}")
    # Send an OPTIONS request to the API endpoint with the headers
    options_response = await test_client.options(api_endpoint)

    for key, value in options_response.headers.items():
        logger.info(f"Header: {key} = {value}")

    # Send a GET request to the API endpoint with the headers
    response = await test_client.get(api_endpoint)

    # Print the response headers
    for key, value in response.headers.items():
        logger.info(f"Header: {key} = {value}")

    # Check if the 'Access-Control-Allow-Origin' header is present
    if "Access-Control-Allow-Origin" in response.headers:
        # Print the allowed origin(s)
        logger.info(f"Access-Control-Allow-Origin: {response.headers['Access-Control-Allow-Origin']}")

        # Check if it allows the origin of your request
        if response.headers["Access-Control-Allow-Origin"] == "*":
            logger.info("CORS is configured to allow all origins.")
        else:
            logger.info("CORS is configured to allow specific origins.")
    else:
        logger.info("Access-Control-Allow-Origin header not found. CORS might not be configured.")

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        # Print the response content
        logger.info(response.text)
    else:
        logger.info(f"Request failed with status code {response.status_code}")


@pytest.mark.parametrize(
    "exc_class,exc_args,expected_status,expected_message",
    [
        (e, (), e.status_code, e.default_message)
        for e in [
            errors.BadRequest,
            errors.Unauthorized,
            errors.NotFound,
            errors.DatabaseConnectionError,
            errors.NoFileProvided,
            errors.FileNameExists,
            errors.ExceedsFileSizeLimit,
            errors.InternalServerError,
            errors.NotImplement,
        ]
    ]
    + [(ValueError, (), 500, "Internal server error"), (RateLimitExceeded, (60,), 429, "Rate limit exceeded")],
)
@pytest.mark.asyncio
async def test_error_handler(
    exc_class: type[Exception], exc_args: tuple[Any, ...], expected_status: int, expected_message: str
) -> None:
    url_path = "/test-error-handler/"

    @app.route(url_path)
    @apis.handle_errors
    async def test_error_fn():
        raise exc_class(*exc_args)

    test_client = app.test_client()
    response = await test_client.get(url_path)
    assert response.status_code == expected_status
    response_body = await response.json
    assert response_body["error"]["data"] == expected_message

    app.url_map._rules_by_endpoint.pop("test_error_fn", None)
    app.view_functions.pop("test_error_fn", None)
