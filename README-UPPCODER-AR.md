# ثقة USDT — إعداد Uppcoder

هذه الحزمة تحتوي ملفات التطبيق في جذر المشروع مباشرة.

## إعداد خدمة Express
- Runtime: Node.js 20 أو أحدث
- Build command: `npm install && npm run db:migrate`
- Start command: `npm start`
- Health check path: `/api/health`

## متغيرات البيئة المطلوبة
- `DATABASE_URL`: رابط PostgreSQL الخاص بالتطبيق.
- `OTP_PEPPER`: قيمة عشوائية سرية طويلة (32 حرفاً أو أكثر).
- `NODE_ENV=production`
- `COOKIE_SECURE=true`
- `COOKIE_SAME_SITE=lax`
- `OTP_DELIVERY_MODE=console` للاختبار فقط.
- `ALLOW_INSECURE_OTP_LOGS=true` للاختبار فقط مع وضع console.

لا تضع الأسرار داخل GitHub أو ملفات الواجهة، ولا ترسلها في المحادثة.

## تنبيه مهم
هذه نسخة تأسيسية: المصادقة وبعض مسارات الإدارة فقط متصلة بالخادم. التجار والتقييمات والبلاغات وباقي العمليات لا تزال تعتمد على بيانات محلية تجريبية. وضع OTP عبر سجلات الخادم للاختبار فقط، ولا تستخدمه مع مستخدمين حقيقيين. لا تعتبر التطبيق جاهزاً للإنتاج قبل استكمال الربط والاختبارات والمراجعة الأمنية.
