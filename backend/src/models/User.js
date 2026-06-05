const supabase = require('../config/database');
const bcrypt = require('bcryptjs');

class User {
  static async create(userData) {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(userData.password, salt);
    
    const { data, error } = await supabase
      .from('users')
      .insert([{
        full_name: userData.fullName,
        email: userData.email,
        phone: userData.phone,
        password: hashedPassword,
        referral_code: 'REF' + Math.random().toString(36).substring(2, 10).toUpperCase(),
        referred_by: userData.referredBy || null
      }])
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  static async findByEmail(email) {
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (error && error.code !== 'PGRST116') throw error;
    return data;
  }

  static async findById(id) {
    const { data, error } = await supabase
      .from('users')
      .select('*, active_package:packages(*)')
      .eq('id', id)
      .single();

    if (error) throw error;
    return data;
  }

  static async findByReferralCode(code) {
    const { data, error } = await supabase
      .from('users')
      .select('id')
      .eq('referral_code', code)
      .single();

    if (error && error.code !== 'PGRST116') throw error;
    return data;
  }

  static async comparePassword(plainPassword, hashedPassword) {
    return await bcrypt.compare(plainPassword, hashedPassword);
  }

  static async updateLastLogin(id) {
    const { error } = await supabase
      .from('users')
      .update({ last_login: new Date().toISOString() })
      .eq('id', id);

    if (error) throw error;
  }
}

module.exports = User;