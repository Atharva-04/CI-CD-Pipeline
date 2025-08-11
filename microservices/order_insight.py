import pymongo

client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["orderdb"]  
orders = db["orders"]

total_orders = orders.count_documents({})

print(f"Total orders in the system: {total_orders}")
print("This is a simple Python script for quick insights!")
