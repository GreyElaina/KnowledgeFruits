module.exports = {
    baseurl: "http://127.0.0.1:5001/api/knowledgefruits/",
    user1: {
        // 此用户不拥有角色
        email: "test1@to2mbn.org",
        // 不能使用的密码：
        // incorrectPassword-_-
        password: "111111"
    },
    user2: {
        // 此用户拥有1个角色
        email: "test2@to2mbn.org",
        password: "222222"
    },

    user3: {
        // 此用户拥有2个角色
        email: "test3@to2mbn.org",
        password: "333333"
    }
};