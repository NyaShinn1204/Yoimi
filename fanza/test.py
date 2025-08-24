product_json = {
  "content_info": {
    "content_id": "govr00110",
    "product_id": "govr00110dl",
    "redirect": "https://wsd-r.dmm.com/020/govr00110/govr00110vrv1lite.wsdcf",
    "recommended_viewing_type": "3d_horizontal_180"
  },
  "cookie_info": {
    "name": "AuthCookie",
    "value": "36003b456059a1dfffada7522d3e265653a855389230430906a305e1735b2e66",
    "expire": 0,
    "path": "/",
    "domain": "dmm.com"
  },
  "status": {
    "code": 0,
    "timestamp": "2025-08-24 15:02:44",
    "version": "v2.0.0"
  }
}


# set session
# url = "https://gw.dmmapis.com/connect/v1/issueSessionId"
target_content = "govr00110vrv1lite.wsdcf"
target_id = "ff43afe5-2d59-4283-99d1-e807943ee5f2"


# get license
# url = f"https://api.webstream.ne.jp/rights/urn:uuid:{target_id}"
# allow_redirects=False
# headers["Location"]
# Example response: https://www.dmm.com/service/android_drm/-/license/?token=8856952a88cceee7a954b4b03f2f4e0cd21d8f8d&content_uri=urn:uuid:ff43afe5-2d59-4283-99d1-e807943ee5f2&product_code=govr00110&classification_code=&license_url=https://api.webstream.ne.jp/api.php/issue_rights_getback

# url = headers["Location"]
# allow_redirects=False
# headers["Location"]
# Example response: https://www.dmm.com/my/-/login/auth/=/path=DRVESRUMTh1PEkYWV1sLGQIKWxlDXBZPCwFSSVYMUFkRAFxYFl9OU1YBQ1daUjlTEwgZGx9aDFISF0UFWgREVToPUxZbGRBRWQZZXQ5YCRg_/

# url = headers["Location"]
# allow_redirects=False
# headers["Location"]
# Example response: https://www.dmm.com/service/digitalapi/android_drm/-/chkpurchase_nc/=/qcache=no/

# url = headers["Location"]
# allow_redirects=False
# headers["Location"]
# Example response: https://api.webstream.ne.jp/api.php/issue_rights_getback?token=8856952a88cceee7a954b4b03f2f4e0cd21d8f8d&rights=interval%3DP14D&hmac=4f40dafebb2d66fd71d064cbf693b0838d467e60

# EXAMPLE RESPONSE HERE
# <rights>
#   <context>
#     <version>1.0</version>
#   </context>
#   <agreement>
#     <asset>
#       <context>
#         <uid>urn:uuid:ff43afe5-2d59-4283-99d1-e807943ee5f2</uid>
#       </context>
#       <KeyInfo>
#         <KeyValue>HZYFpv8TSum3iN8mDTSZGQ==</KeyValue>
#       </KeyInfo>
#     </asset>
#     <permission>
#       <play>
#         <constraint>
#           <datetime>
#           </datetime>
#           <interval>P14D</interval>
#         </constraint>
#       </play>
#     </permission>
#   </agreement>
# </rights>
# 
