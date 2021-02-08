from flask import Flask,request
import bcrypt
from pymongo import MongoClient
from flask_restful import Api,Resource
from flask import jsonify

#test=db.demo.insert({"count":1})
app=Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://127.0.0.1:27017")
db = client.mydb
user = db["Users"]

"""  Register User for First Time """

def verify_psw(username,password):
    print("user decode password")
    print(password)
    #db.users.find({}).sort({"_id":1}).limit(1);
    #db.users.find({"Dept" : "IT"}).sort({"_id":1}).limit(1);
    #existuser=user.find({"username": username}).sort([("password",1),("_id",0),("TOken",0),("username",0),("secret_word",0)]).limit(1)
    user_pass=user.find({"username":username})[0]['password']
    if bcrypt.checkpw(password.encode("utf8"),user_pass):
        print("password Match!!!!!!")
        return True
    else:
        print("password Not Match@@@@@@@")
        return False

    #hashUserpass=bcrypt.hashpw(password.encode('utf8'),bcrypt.gensalt())
    #print(hashUserpass)
    # existuser=user.find(
    #     {"username":username})[0]['password']

    #if bcrypt.checkpw(password.encode('utf8'),user_pass.encode('utf8'))==user_pass:
     #   return True
    #else:
    #    return False
def tokens_count(username):
    token=user.find(
        {"username":username}
    )[0]['Tokens']
    return token      
def checkUser(username):
    anyUser=True
    if not anyUser:
        return False
    else:
        return True   
#for Register user for the first time  
# @param username,password              
class Register(Resource):
    def post(self):
        post_data=request.get_json()
        username=post_data['username']
        password=post_data['password']
        secret_word=""
        TOkens=10

        hash_password=bcrypt.hashpw(password.encode('utf8'),bcrypt.gensalt())
        print("the username we get is"+username)
        print("the hashed password is")
        print(str(hash_password))
        userrecord=checkUser(username)
        if  not userrecord:
            not_foundResponse={
                'status':301,
                'Message':'Username Exist'
            }
            return jsonify(not_foundResponse)
        # Token=tokens_count(username)   
        # if Token > 0:
        else:
            user.insert({'username':username,'password':hash_password,'secret_word':secret_word,'Tokens':TOkens})   
            register_response={
                'status':200,
                'Message':'Hey you have successfully registered'
            }
            return jsonify(register_response)

# for store secret word with  having the enough tokens to use 
#@param  username,password,secretword
class StoreSentence(Resource):
    def post(self):
        post_data=request.get_json()
        username=post_data['username']
        password=post_data['password']
        secret_word=post_data['secret_word']
        
        verify_psword=verify_psw(username,password)
        if not verify_psword:
            user_notFoundResponse={
                'status':302,
                'Message':'User Not exist '
            }
            return jsonify(user_notFoundResponse)
        Token=tokens_count(username)
        if Token < 0:
            noTokenResponse={
                'response':303,
                'Message':'You Dont have Enough Token To store These Secret'
            }
            return jsonify(noTokenResponse)
        user.update({
            'username':username
        },{'$set':{'secret_word':secret_word,'Tokens':Token-1}}) 
        update_response={
            'status':200,
            'Message':'Your secret word Sucessfully saved Please check it'
        }
        return jsonify(update_response)

#for retrieve the secret word with the valid no of tokens api register class 
#@param  username,password
class getSecretWord(Register):
    def post(self):
        post_data=request.get_json()
        username=post_data['username']
        password=post_data['password']
        verfy_user=verify_psw(username,password)
        if not verfy_user:
            return_response={
                'status':305,
                'Message':'username password not exist'
            }
            return jsonify(return_response)
        token=tokens_count(username)
        if token <= 0:
            token_response={
                'status':308,
                'Message':'You dont have enough Token'
            }
            return jsonify(token_response)
        else:
            secretWord=user.find({'username':username})[0]['secret_word']
            user.update({'username':username},{'$set':{'Tokens':token-1}})
            sentence_response={
                'status':200,
                'Your Secret Word':secretWord
            }
            return jsonify(sentence_response)

api.add_resource(getSecretWord,'/getword')            
api.add_resource(Register,'/register')
api.add_resource(StoreSentence,'/saveword')  

#usercout=db['demo']
# usercout.insert({
#     'user_count':0
# })
#new_val=usercout.find({},{'user_count':1,'_id':0})
#print(new_val)

# @app.route("/about")
# def helloWorld():
#     print("the function is calling from hello")
    
#     return "hello our route is working and also print some result so happy coding"

# @app.route('/getCOunt/<username>',methods=['GET'])
# def getUser(username):
#     prev_num = demo.find({})[0]['num_of_users']
#     new_num = prev_num + 1
#     demo.update({},{'$set':{'num_of_users':new_num}})
#     #db.student.find({}, {roll:1, _id:0})
#     newval=new_num+1
#     print("the username we get is"+username)
#     return ("Hello {}").format(newval)
if __name__=='__main__':
    app.run(debug=True)
