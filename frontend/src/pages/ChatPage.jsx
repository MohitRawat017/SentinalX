import React, { useState, useEffect, useRef, useCallback } from 'react';
import useStore from '../store';
import { chatAPI } from '../api';
import {
  HiPaperAirplane,
  HiShieldCheck,
  HiExclamationTriangle,
  HiUserPlus,
  HiChatBubbleLeftRight,
  HiXMark,
} from 'react-icons/hi2';

export default function ChatPage() {
  const { wallet, addNotification } = useStore();
  const [contacts, setContacts] = useState([]);
  const [selectedPeer, setSelectedPeer] = useState('');
  const [messages, setMessages] = useState([]);
  const [text, setText] = useState('');
  const [sending, setSending] = useState(false);
  const [newPeer, setNewPeer] = useState('');
  const [showNewChat, setShowNewChat] = useState(false);
  const [warning, setWarning] = useState(null);
  const [wsStatus, setWsStatus] = useState('disconnected');
  const messagesEndRef = useRef(null);
  const wsRef = useRef(null);
  const selectedPeerRef = useRef('');

  // Keep ref in sync with state so WebSocket handler always has latest value
  useEffect(() => {
    selectedPeerRef.current = selectedPeer;
  }, [selectedPeer]);

  // Fetch contacts on mount
  useEffect(() => {
    if (wallet) fetchContacts();
  }, [wallet]);

  // Connect WebSocket with auto-reconnect
  useEffect(() => {
    if (!wallet) return;
    let reconnectTimer = null;
    let alive = true;

    function connect() {
      const url = chatAPI.wsUrl(wallet);
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        setWsStatus('connected');
        // Heartbeat every 25s to keep Render connection alive
        ws._heartbeat = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) ws.send('ping');
        }, 25000);
      };

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'new_message') {
          const peer = selectedPeerRef.current;
          // Show message if it's from or to the currently selected peer
          if (data.sender === peer || data.receiver === peer) {
            setMessages((prev) => {
              // Dedupe by message_id
              if (prev.some((m) => m.id === data.message_id)) return prev;
              return [...prev, {
                id: data.message_id,
                sender: data.sender,
                receiver: data.receiver || wallet.toLowerCase(),
                content: data.content,
                redacted: data.redacted || false,
                risk_detected: data.risk_detected || false,
                timestamp: data.timestamp,
              }];
            });
          }
          fetchContacts();
        }
      };

      ws.onclose = () => {
        setWsStatus('disconnected');
        if (ws._heartbeat) clearInterval(ws._heartbeat);
        // Auto-reconnect after 3s
        if (alive) {
          reconnectTimer = setTimeout(connect, 3000);
        }
      };

      ws.onerror = () => {
        ws.close();
      };
    }

    connect();

    return () => {
      alive = false;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      const ws = wsRef.current;
      if (ws) {
        if (ws._heartbeat) clearInterval(ws._heartbeat);
        ws.close();
      }
    };
  }, [wallet]);

  // Fetch messages when peer changes
  useEffect(() => {
    if (selectedPeer) fetchMessages();
  }, [selectedPeer]);

  // Auto-scroll
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const fetchContacts = async () => {
    try {
      const res = await chatAPI.contacts(wallet);
      setContacts(res.data.contacts || []);
    } catch (err) {
      console.error('Failed to load contacts', err);
    }
  };

  const fetchMessages = async () => {
    try {
      const res = await chatAPI.messages(wallet, selectedPeer);
      setMessages(res.data.messages || []);
    } catch (err) {
      console.error('Failed to load messages', err);
    }
  };

  const handleSend = async () => {
    if (!text.trim() || !selectedPeer) return;
    setSending(true);
    setWarning(null);

    try {
      const res = await chatAPI.send({
        sender_wallet: wallet,
        receiver_wallet: selectedPeer,
        text: text.trim(),
        use_llm: true,
        force_send: false,
      });

      if (res.data.status === 'warning') {
        setWarning(res.data);
      } else {
        setText('');
        fetchMessages();
        fetchContacts();
      }
    } catch (err) {
      addNotification({ type: 'error', title: 'Send Failed', message: 'Could not send message.' });
    }
    setSending(false);
  };

  const handleForceSend = async () => {
    setSending(true);
    try {
      await chatAPI.send({
        sender_wallet: wallet,
        receiver_wallet: selectedPeer,
        text: text.trim(),
        use_llm: false,
        force_send: true,
      });
      setText('');
      setWarning(null);
      fetchMessages();
      fetchContacts();
      addNotification({ type: 'warning', title: 'Sent with Override', message: 'Sensitive content was sent. This is logged in the audit trail.' });
    } catch (err) {
      addNotification({ type: 'error', title: 'Send Failed', message: 'Could not send message.' });
    }
    setSending(false);
  };

  const handleRedactSend = async () => {
    setSending(true);
    try {
      await chatAPI.redact({
        sender_wallet: wallet,
        receiver_wallet: selectedPeer,
        text: text.trim(),
      });
      setText('');
      setWarning(null);
      fetchMessages();
      fetchContacts();
      addNotification({ type: 'success', title: 'Redacted & Sent', message: 'Sensitive data was redacted before sending.' });
    } catch (err) {
      addNotification({ type: 'error', title: 'Redact Failed', message: 'Could not redact and send.' });
    }
    setSending(false);
  };

  const handleStartChat = () => {
    const addr = newPeer.trim().toLowerCase();
    if (!addr.startsWith('0x') || addr.length !== 42) {
      addNotification({ type: 'error', title: 'Invalid Address', message: 'Enter a valid 0x wallet address (42 chars).' });
      return;
    }
    setSelectedPeer(addr);
    setNewPeer('');
    setShowNewChat(false);
    setMessages([]);
  };

  const formatAddr = (addr) => addr ? `${addr.slice(0, 6)}...${addr.slice(-4)}` : '';
  const formatTime = (ts) => ts ? new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <HiChatBubbleLeftRight className="w-7 h-7 text-blue-400" />
            Secure Chat
          </h1>
          <p className="text-gray-400 text-sm mt-1">
            End-to-end messaging with GuardLayer DLP protection
          </p>
        </div>
        <div className="flex items-center gap-1.5">
          <div className={`w-2 h-2 rounded-full ${wsStatus === 'connected' ? 'bg-emerald-500 pulse-dot' : 'bg-gray-600'}`} />
          <span className="text-xs text-gray-500">{wsStatus === 'connected' ? 'Live' : 'Reconnecting...'}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4" style={{ height: 'calc(100vh - 14rem)' }}>
        {/* Contacts Panel */}
        <div className="glass-card p-4 lg:col-span-1 flex flex-col">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-gray-300">Contacts</h3>
            <button
              onClick={() => setShowNewChat(!showNewChat)}
              className="p-1.5 rounded-lg hover:bg-white/10 text-gray-400 hover:text-blue-400 transition-all"
              title="New Chat"
            >
              <HiUserPlus className="w-4 h-4" />
            </button>
          </div>

          {showNewChat && (
            <div className="mb-3 space-y-2">
              <input
                value={newPeer}
                onChange={(e) => setNewPeer(e.target.value)}
                placeholder="0x... wallet address"
                className="w-full bg-sentinel-dark border border-sentinel-border rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:border-blue-500/50 focus:outline-none font-mono"
                onKeyDown={(e) => e.key === 'Enter' && handleStartChat()}
              />
              <button
                onClick={handleStartChat}
                className="w-full px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium transition-all"
              >
                Start Chat
              </button>
            </div>
          )}

          <div className="flex-1 overflow-y-auto space-y-1">
            {contacts.length === 0 && !showNewChat ? (
              <p className="text-gray-600 text-xs text-center py-8">
                No conversations yet.<br />Click + to start a chat.
              </p>
            ) : (
              contacts.map((c) => (
                <button
                  key={c.wallet}
                  onClick={() => { setSelectedPeer(c.wallet); setWarning(null); }}
                  className={`w-full text-left p-3 rounded-lg transition-all ${
                    selectedPeer === c.wallet
                      ? 'bg-blue-500/20 border border-blue-500/30'
                      : 'hover:bg-white/5 border border-transparent'
                  }`}
                >
                  <p className="text-sm font-mono text-white">{formatAddr(c.wallet)}</p>
                  <div className="flex items-center justify-between mt-1">
                    <span className="text-xs text-gray-500">{c.message_count} msgs</span>
                    {c.last_message && (
                      <span className="text-xs text-gray-600">
                        {new Date(c.last_message).toLocaleDateString()}
                      </span>
                    )}
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        {/* Chat Panel */}
        <div className="glass-card p-4 lg:col-span-3 flex flex-col">
          {!selectedPeer ? (
            <div className="flex-1 flex items-center justify-center">
              <div className="text-center">
                <HiChatBubbleLeftRight className="w-12 h-12 text-gray-700 mx-auto mb-3" />
                <p className="text-gray-500">Select a contact or start a new chat</p>
              </div>
            </div>
          ) : (
            <>
              {/* Header */}
              <div className="flex items-center justify-between pb-3 border-b border-sentinel-border mb-3">
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 rounded-full bg-gradient-to-br from-purple-500 to-blue-500 flex items-center justify-center text-white text-xs font-bold">
                    {selectedPeer.slice(2, 4).toUpperCase()}
                  </div>
                  <div>
                    <p className="text-sm font-mono text-white">{formatAddr(selectedPeer)}</p>
                    <p className="text-xs text-gray-500">GuardLayer Protected</p>
                  </div>
                </div>
                <div className="flex items-center gap-1 text-xs text-emerald-400">
                  <HiShieldCheck className="w-4 h-4" />
                  DLP Active
                </div>
              </div>

              {/* Messages */}
              <div className="flex-1 overflow-y-auto space-y-3 mb-3 pr-1">
                {messages.length === 0 ? (
                  <div className="flex items-center justify-center h-full">
                    <p className="text-gray-600 text-sm">No messages yet. Say hello!</p>
                  </div>
                ) : (
                  messages.map((m) => {
                    const isMine = m.sender === wallet?.toLowerCase();
                    return (
                      <div key={m.id} className={`flex ${isMine ? 'justify-end' : 'justify-start'}`}>
                        <div className={`max-w-[70%] px-4 py-2.5 rounded-2xl ${
                          isMine
                            ? 'bg-blue-600 text-white rounded-br-md'
                            : 'bg-sentinel-dark border border-sentinel-border text-gray-200 rounded-bl-md'
                        }`}>
                          <p className="text-sm whitespace-pre-wrap break-words">{m.content}</p>
                          <div className={`flex items-center gap-2 mt-1 ${isMine ? 'justify-end' : 'justify-start'}`}>
                            {m.redacted && (
                              <span className="text-xs px-1.5 py-0.5 rounded bg-yellow-500/20 text-yellow-300">
                                redacted
                              </span>
                            )}
                            {m.risk_detected && !m.redacted && (
                              <span className="text-xs px-1.5 py-0.5 rounded bg-red-500/20 text-red-300">
                                override
                              </span>
                            )}
                            <span className={`text-xs ${isMine ? 'text-blue-200' : 'text-gray-500'}`}>
                              {formatTime(m.timestamp)}
                            </span>
                          </div>
                        </div>
                      </div>
                    );
                  })
                )}
                <div ref={messagesEndRef} />
              </div>

              {/* DLP Warning */}
              {warning && (
                <div className="mb-3 p-4 rounded-xl border border-red-500/30 bg-red-500/5">
                  <div className="flex items-center gap-2 mb-2">
                    <HiExclamationTriangle className="w-5 h-5 text-red-400" />
                    <span className="font-semibold text-red-400 text-sm">Sensitive Data Detected</span>
                    <button onClick={() => setWarning(null)} className="ml-auto text-gray-500 hover:text-white">
                      <HiXMark className="w-4 h-4" />
                    </button>
                  </div>
                  <p className="text-xs text-gray-400 mb-3">{warning.warning}</p>
                  {warning.scan_result?.categories?.length > 0 && (
                    <div className="flex flex-wrap gap-1 mb-3">
                      {warning.scan_result.categories.map((cat, i) => (
                        <span key={i} className="text-xs px-2 py-0.5 rounded-full bg-red-500/20 text-red-300 border border-red-500/30">
                          {cat}
                        </span>
                      ))}
                    </div>
                  )}
                  <div className="flex gap-2">
                    <button
                      onClick={handleForceSend}
                      disabled={sending}
                      className="flex-1 px-3 py-2 rounded-lg bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/30 text-sm font-medium transition-all disabled:opacity-50"
                    >
                      Send Anyway
                    </button>
                    <button
                      onClick={handleRedactSend}
                      disabled={sending}
                      className="flex-1 px-3 py-2 rounded-lg bg-blue-500/20 text-blue-400 border border-blue-500/30 hover:bg-blue-500/30 text-sm font-medium transition-all disabled:opacity-50"
                    >
                      Redact & Send
                    </button>
                    <button
                      onClick={() => { setWarning(null); setText(''); }}
                      className="px-3 py-2 rounded-lg bg-white/5 text-gray-400 border border-white/10 hover:bg-white/10 text-sm font-medium transition-all"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}

              {/* Input */}
              <div className="flex gap-2">
                <input
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && handleSend()}
                  placeholder="Type a message..."
                  className="flex-1 bg-sentinel-dark border border-sentinel-border rounded-xl px-4 py-3 text-white placeholder-gray-600 focus:border-blue-500/50 focus:outline-none text-sm"
                  disabled={sending}
                />
                <button
                  onClick={handleSend}
                  disabled={sending || !text.trim()}
                  className="px-4 py-3 rounded-xl bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-white transition-all disabled:opacity-50"
                >
                  {sending ? (
                    <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  ) : (
                    <HiPaperAirplane className="w-5 h-5" />
                  )}
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
