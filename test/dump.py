from entrancebar import entrance_file
db = entrance_file('@/database/connector.py').SelectedDatabase
model = entrance_file('@/database/model.py')

import ujson
data = ujson.loads(open("./test/profile.json").read())

with db.atomic():
    for i in data:
        model.Profile.create(**i)