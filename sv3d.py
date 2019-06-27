"""
Inspired by skinview3d(https://github.com/bs-community/skinview3d)
"""

def listget(li, index):
    try:
        return li[index]
    except IndexError:
        return 0

def hasTransparency(context, x1, y1, w, h):
    imgData = list(context.crop((x1, y1, x1+w, y1+h)).getdata())
    for x in range(w):
        for y in range(h):
            offset = (x + y * w) * 4
            if listget(imgData, offset + 3) == (0,0,0,0):
                return False
    return True

def computeSkinScale(width):
    return int(width / 64)

def isSilmSkin(context):
    scale = computeSkinScale(context.size[0])
    checkArea = lambda x, y, w, h: hasTransparency(context, x * scale, y * scale, w * scale, h * scale)
    return not(checkArea(50, 16, 2, 4) | checkArea(54, 20, 2, 12) | checkArea(42, 48, 2, 4) | checkArea(46, 52, 2, 12))

if __name__ == "__main__":
    from PIL import Image
    assert isSilmSkin(Image.open("./data/texture/1a642230408249749b82308dac69e7b8.png")) == False
    assert isSilmSkin(Image.open("./data/texture/490bd08f1cc7fce67f2e7acb877e5859d1605f4ffb0893b07607deae5e05becc.png")) == True