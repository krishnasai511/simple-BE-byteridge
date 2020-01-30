const mongoose = require('mongoose');
const schema = mongoose.Schema;

const logsSchema = new schema({
    user_id: {
        type: String,
        required: true
    },
    login_time: {
        type: String,
        required: true
    },
    logout_time: {
        type: String,
        default: ''
    },
    client_ip: {
        type: String,
        required: true
    }
})

logsSchema.set('toJSON', { virtuals: true });


const UserLogs = mongoose.model('userlogs', logsSchema);
module.exports = UserLogs;