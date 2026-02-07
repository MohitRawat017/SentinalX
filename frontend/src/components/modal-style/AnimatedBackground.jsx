import React from 'react';

/**
 * AnimatedBackground - Pure CSS animated background
 * Creates a dynamic, floating particle effect without Three.js dependencies
 * Much more compatible and still visually appealing
 */
export default function AnimatedBackground() {
    return (
        <div className="absolute inset-0 z-0 overflow-hidden">
            {/* Animated gradient mesh */}
            <div className="absolute inset-0 bg-[#0a0a0f]" />

            {/* Floating orbs with CSS animations */}
            <div
                className="absolute w-[600px] h-[600px] rounded-full opacity-30 blur-[100px]"
                style={{
                    background: 'radial-gradient(circle, rgba(16,185,129,0.4) 0%, transparent 70%)',
                    top: '10%',
                    left: '20%',
                    animation: 'float1 20s ease-in-out infinite',
                }}
            />
            <div
                className="absolute w-[500px] h-[500px] rounded-full opacity-25 blur-[80px]"
                style={{
                    background: 'radial-gradient(circle, rgba(20,184,166,0.4) 0%, transparent 70%)',
                    top: '40%',
                    right: '10%',
                    animation: 'float2 25s ease-in-out infinite',
                }}
            />
            <div
                className="absolute w-[400px] h-[400px] rounded-full opacity-20 blur-[60px]"
                style={{
                    background: 'radial-gradient(circle, rgba(59,130,246,0.3) 0%, transparent 70%)',
                    bottom: '20%',
                    left: '30%',
                    animation: 'float3 18s ease-in-out infinite',
                }}
            />

            {/* Particle dots */}
            <div className="absolute inset-0">
                {[...Array(50)].map((_, i) => (
                    <div
                        key={i}
                        className="absolute w-1 h-1 bg-emerald-500/30 rounded-full"
                        style={{
                            left: `${Math.random() * 100}%`,
                            top: `${Math.random() * 100}%`,
                            animation: `twinkle ${3 + Math.random() * 4}s ease-in-out infinite`,
                            animationDelay: `${Math.random() * 5}s`,
                        }}
                    />
                ))}
            </div>

            {/* Grid pattern overlay */}
            <div
                className="absolute inset-0 opacity-[0.03]"
                style={{
                    backgroundImage: `
            linear-gradient(rgba(255,255,255,0.1) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255,255,255,0.1) 1px, transparent 1px)
          `,
                    backgroundSize: '60px 60px',
                }}
            />

            {/* Inline keyframes */}
            <style>{`
        @keyframes float1 {
          0%, 100% { transform: translate(0, 0) scale(1); }
          33% { transform: translate(30px, -50px) scale(1.1); }
          66% { transform: translate(-20px, 30px) scale(0.9); }
        }
        @keyframes float2 {
          0%, 100% { transform: translate(0, 0) scale(1); }
          33% { transform: translate(-40px, 30px) scale(1.05); }
          66% { transform: translate(20px, -40px) scale(0.95); }
        }
        @keyframes float3 {
          0%, 100% { transform: translate(0, 0) scale(1); }
          33% { transform: translate(20px, 40px) scale(1.1); }
          66% { transform: translate(-30px, -20px) scale(0.9); }
        }
        @keyframes twinkle {
          0%, 100% { opacity: 0.3; transform: scale(1); }
          50% { opacity: 0.8; transform: scale(1.5); }
        }
      `}</style>
        </div>
    );
}
