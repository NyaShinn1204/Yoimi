var h = {"keys":[{"kty":"oct","k":"GF5kEzJ57JMwj4ANiVjXK96YmupfqKJEGoRxcEr5D2xc.DyE8UXxDHTRoHqSFv8MnVv5.4a9dd24b59a7b15308a1fe46e31c7fa8","kid":"uIFdYNVYShGCkN8ufLd0mA"}],"type":"temporary"}
var d = h["keys"][0]
var w = d["k"]
var p = w["slice"](w["indexOf"](".") + 1)
var f = function (r, n) {
    return r + n
}
decrypt_uuid = p["slice"](f(p["indexOf"]("."), 1))
console.log("O:", decrypt_uuid)

decrypt_y = (o = r, u = Cr(l, e, g), o["lib"]["WordArray"]["create"](u));
console.log("Y:", decrypt_y)