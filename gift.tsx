import React, { useState, useEffect } from 'react';
import {
  View, Text, StyleSheet, TouchableOpacity, TextInput,
  ScrollView, Platform, ActivityIndicator, Alert,
} from 'react-native';
import { useRouter } from 'expo-router';
import { Ionicons } from '@expo/vector-icons';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { Colors, API_BASE } from '../utils/constants';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

interface Gift {
  gifted_to_email: string;
  gifted_to_name: string;
  plan_id: string;
  gifted_by: string;
  created_at: string;
}

export default function GiftScreen() {
  const router = useRouter();
  const insets = useSafeAreaInsets();
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [planId, setPlanId] = useState('tier2');
  const [sending, setSending] = useState(false);
  const [gifts, setGifts] = useState<Gift[]>([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState('');

  useEffect(() => { loadGifts(); }, []);

  const getHeaders = async () => {
    const token = await AsyncStorage.getItem('access_token');
    const h: any = { 'Content-Type': 'application/json' };
    if (token) h.Authorization = `Bearer ${token}`;
    return h;
  };

  const loadGifts = async () => {
    try {
      const headers = await getHeaders();
      const res = await fetch(`${API_BASE}/admin/gifts`, { headers, credentials: 'include' });
      if (res.ok) {
        const data = await res.json();
        setGifts(data.gifts || []);
      }
    } catch (e) { console.error('Load error:', e); }
    setLoading(false);
  };

  const sendGift = async () => {
    if (!email) {
      setMessage('Please enter an email address');
      return;
    }
    setSending(true);
    setMessage('');
    try {
      const headers = await getHeaders();
      const res = await fetch(`${API_BASE}/admin/gift`, {
        method: 'POST', headers, credentials: 'include',
        body: JSON.stringify({ email, plan_id: planId, name }),
      });
      const data = await res.json();
      if (res.ok) {
        setMessage(data.message || 'Gift sent!');
        setEmail('');
        setName('');
        loadGifts();
      } else {
        setMessage(data.detail || 'Failed to send gift');
      }
    } catch (e) {
      setMessage('Error sending gift');
    }
    setSending(false);
  };

  const revokeGift = async (giftEmail: string) => {
    try {
      const headers = await getHeaders();
      await fetch(`${API_BASE}/admin/gift/${giftEmail}`, {
        method: 'DELETE', headers, credentials: 'include',
      });
      loadGifts();
    } catch (e) { console.error('Revoke error:', e); }
  };

  const formatDate = (iso: string) => {
    try {
      return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    } catch { return iso; }
  };

  return (
    <View style={[s.container, { paddingTop: insets.top }]}>
      <View style={s.header}>
        <TouchableOpacity testID="gift-back-btn" onPress={() => router.back()} style={s.backBtn}>
          <Ionicons name="chevron-back" size={24} color={Colors.textPrimary} />
        </TouchableOpacity>
        <View style={s.headerCenter}>
          <Text style={s.headerTitle}>GIFT</Text>
          <Text style={s.headerSub}>SEND FREE SUBSCRIPTIONS</Text>
        </View>
        <View style={s.backBtn} />
      </View>

      <ScrollView style={s.scroll} showsVerticalScrollIndicator={false} keyboardShouldPersistTaps="handled">
        {/* Send Gift Form */}
        <View style={s.formCard}>
          <Ionicons name="gift" size={32} color={Colors.greenSafe} />
          <Text style={s.formTitle}>GIFT A FREE FIRE APP</Text>
          <Text style={s.formDesc}>Send a free subscription to anyone. It stays free forever.</Text>

          <Text style={s.label}>RECIPIENT EMAIL</Text>
          <TextInput testID="gift-email" style={s.input} value={email} onChangeText={setEmail}
            placeholder="their@email.com" placeholderTextColor={Colors.textSecondary}
            autoCapitalize="none" keyboardType="email-address" />

          <Text style={s.label}>RECIPIENT NAME (OPTIONAL)</Text>
          <TextInput testID="gift-name" style={s.input} value={name} onChangeText={setName}
            placeholder="Their name" placeholderTextColor={Colors.textSecondary} />

          <Text style={s.label}>PLAN TO GIFT</Text>
          <View style={s.planRow}>
            <TouchableOpacity testID="gift-tier1" style={[s.planOption, planId === 'tier1' && s.planSelected]}
              onPress={() => setPlanId('tier1')}>
              <Text style={[s.planOptionText, planId === 'tier1' && s.planSelectedText]}>TIER ONE</Text>
              <Text style={s.planPrice}>$3.99 value</Text>
            </TouchableOpacity>
            <TouchableOpacity testID="gift-tier2" style={[s.planOption, planId === 'tier2' && s.planSelectedGreen]}
              onPress={() => setPlanId('tier2')}>
              <Text style={[s.planOptionText, planId === 'tier2' && s.planSelectedText]}>TIER TWO</Text>
              <Text style={s.planPrice}>$7.99 value</Text>
            </TouchableOpacity>
          </View>

          {message ? (
            <View style={[s.msgBox, message.includes('gifted') || message.includes('Gift') ? s.msgSuccess : s.msgError]}>
              <Text style={s.msgText}>{message}</Text>
            </View>
          ) : null}

          <TouchableOpacity testID="send-gift-btn" style={s.sendBtn} onPress={sendGift} disabled={sending}>
            {sending ? <ActivityIndicator color={Colors.textInverse} /> : (
              <>
                <Ionicons name="gift" size={20} color={Colors.textInverse} />
                <Text style={s.sendBtnText}>SEND FREE FIRE APP</Text>
              </>
            )}
          </TouchableOpacity>
        </View>

        {/* Gift History */}
        <Text style={s.sectionTitle}>GIFTED SUBSCRIPTIONS</Text>
        {loading ? (
          <ActivityIndicator color={Colors.yellowCaution} />
        ) : gifts.length === 0 ? (
          <View style={s.empty}>
            <Text style={s.emptyText}>No gifts sent yet</Text>
          </View>
        ) : (
          gifts.map((gift, i) => (
            <View key={i} style={s.giftCard}>
              <View style={s.giftHeader}>
                <Ionicons name="gift" size={18} color={Colors.greenSafe} />
                <View style={s.giftInfo}>
                  <Text style={s.giftEmail}>{gift.gifted_to_email}</Text>
                  <Text style={s.giftName}>{gift.gifted_to_name || 'No name'}</Text>
                </View>
                <TouchableOpacity style={s.revokeBtn} onPress={() => revokeGift(gift.gifted_to_email)}>
                  <Ionicons name="close-circle" size={20} color={Colors.redCritical} />
                </TouchableOpacity>
              </View>
              <View style={s.giftDetails}>
                <Text style={s.giftPlan}>{gift.plan_id.toUpperCase()} — FREE FOREVER</Text>
                <Text style={s.giftDate}>{formatDate(gift.created_at)}</Text>
              </View>
            </View>
          ))
        )}

        <View style={{ height: 40 }} />
      </ScrollView>
    </View>
  );
}

const s = StyleSheet.create({
  container: { flex: 1, backgroundColor: Colors.base },
  header: { flexDirection: 'row', alignItems: 'center', paddingHorizontal: 16, paddingVertical: 12 },
  backBtn: { width: 44, height: 44, borderRadius: 12, backgroundColor: Colors.surface, alignItems: 'center', justifyContent: 'center', borderWidth: 1, borderColor: Colors.border },
  headerCenter: { flex: 1, alignItems: 'center' },
  headerTitle: { fontSize: 20, fontWeight: '900', color: Colors.textPrimary, letterSpacing: 3 },
  headerSub: { fontSize: 9, fontWeight: '700', color: Colors.textSecondary, letterSpacing: 2, marginTop: 2 },
  scroll: { flex: 1, paddingHorizontal: 16 },
  formCard: { backgroundColor: Colors.surface, borderRadius: 16, padding: 20, marginTop: 8, borderWidth: 1, borderColor: Colors.greenSafe, alignItems: 'center' },
  formTitle: { fontSize: 18, fontWeight: '900', color: Colors.greenSafe, letterSpacing: 2, marginTop: 10 },
  formDesc: { fontSize: 13, color: Colors.textSecondary, textAlign: 'center', marginTop: 4, marginBottom: 16 },
  label: { fontSize: 10, fontWeight: '800', color: Colors.textSecondary, letterSpacing: 2, alignSelf: 'flex-start', marginTop: 10, marginBottom: 4 },
  input: { height: 48, backgroundColor: Colors.surfaceElevated, borderRadius: 10, paddingHorizontal: 14, fontSize: 15, color: Colors.textPrimary, borderWidth: 1, borderColor: Colors.border, width: '100%' },
  planRow: { flexDirection: 'row', gap: 10, marginTop: 6, width: '100%' },
  planOption: { flex: 1, backgroundColor: Colors.surfaceElevated, borderRadius: 10, padding: 14, alignItems: 'center', borderWidth: 1, borderColor: Colors.border },
  planSelected: { borderColor: Colors.yellowCaution, backgroundColor: 'rgba(255,204,0,0.1)' },
  planSelectedGreen: { borderColor: Colors.greenSafe, backgroundColor: 'rgba(52,199,89,0.1)' },
  planOptionText: { fontSize: 14, fontWeight: '800', color: Colors.textSecondary, letterSpacing: 1 },
  planSelectedText: { color: Colors.textPrimary },
  planPrice: { fontSize: 11, color: Colors.textSecondary, marginTop: 2 },
  msgBox: { width: '100%', padding: 12, borderRadius: 10, marginTop: 10 },
  msgSuccess: { backgroundColor: 'rgba(52,199,89,0.15)', borderWidth: 1, borderColor: 'rgba(52,199,89,0.3)' },
  msgError: { backgroundColor: 'rgba(255,59,48,0.15)', borderWidth: 1, borderColor: 'rgba(255,59,48,0.3)' },
  msgText: { fontSize: 13, color: Colors.textPrimary, textAlign: 'center' },
  sendBtn: { flexDirection: 'row', height: 52, backgroundColor: Colors.greenSafe, borderRadius: 14, alignItems: 'center', justifyContent: 'center', gap: 8, width: '100%', marginTop: 14 },
  sendBtnText: { fontSize: 15, fontWeight: '800', color: Colors.textInverse, letterSpacing: 1 },
  sectionTitle: { fontSize: 13, fontWeight: '800', color: Colors.textSecondary, letterSpacing: 3, marginTop: 28, marginBottom: 12 },
  empty: { alignItems: 'center', paddingVertical: 24 },
  emptyText: { fontSize: 14, color: Colors.textSecondary },
  giftCard: { backgroundColor: Colors.surface, borderRadius: 12, padding: 14, marginBottom: 10, borderWidth: 1, borderColor: Colors.border },
  giftHeader: { flexDirection: 'row', alignItems: 'center', gap: 10 },
  giftInfo: { flex: 1 },
  giftEmail: { fontSize: 15, fontWeight: '700', color: Colors.textPrimary },
  giftName: { fontSize: 12, color: Colors.textSecondary },
  revokeBtn: { padding: 4 },
  giftDetails: { flexDirection: 'row', justifyContent: 'space-between', marginTop: 8, paddingLeft: 28 },
  giftPlan: { fontSize: 12, fontWeight: '800', color: Colors.greenSafe, letterSpacing: 1 },
  giftDate: { fontSize: 12, color: Colors.textSecondary },
});
