import asyncio
import peewee
import peewee_async

# Nothing special, just define model and database:

database = peewee_async.PostgresqlDatabase(
    "test",
    host="localhost",
    port=5432,
    user="postgres",
    password="saver3234r4y67uy"
)

class TestModel(peewee.Model):
    text = peewee.CharField()

    class Meta:
        database = database

# Look, sync code is working!

TestModel.create_table(True)
TestModel.create(text="Yo, I can do it sync!")
database.close()

# Create async models manager:

objects = peewee_async.Manager(database)

# No need for sync anymore!

database.set_allow_sync(False)

def TT():
    return objects.execute(TestModel.select())

async def handler():
    await objects.create(TestModel, text="Not bad. Watch this, I'm async!")
    all_objects = await TT()
    print(all_objects)
    for obj in all_objects:
        print(obj.text)

loop = asyncio.get_event_loop()
loop.run_until_complete(handler())
loop.close()

# Clean up, can do it sync again:
with objects.allow_sync():
    TestModel.drop_table(True)

# Expected output:
# Yo, I can do it sync!
# Not bad. Watch this, I'm async!