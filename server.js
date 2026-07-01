require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const speakeasy = require('speakeasy'); // <-- Nueva librería

const app = express();
app.use(cors({
  origin: '*', // Permitir desde cualquier origen para descartar bloqueos
  methods: ['GET', 'POST', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(cors({ origin: '*' }));
app.options('*', cors()); // <--- ¡ESTO ES VITAL PARA EL PREFLIGHT CORS!
app.use(express.json());

// Conexión a MongoDB Atlas
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Conectado exitosamente a MongoDB Atlas'))
    .catch(err => console.error('Error al conectar a Atlas:', err));

const AuthSchema = new mongoose.Schema({
    servicio: String,
    cuenta: String,
    secret: String,
    estado: { type: String, default: 'Pendiente' },
    escaneado: { type: Boolean, default: false }, // <-- NUEVA LÍNEA
    fecha: { type: Date, default: Date.now }
});
const Auth = mongoose.model('Auth', AuthSchema);
// El celular avisa que ya escaneó el QR
app.post('/api/auth/scanned', async (req, res) => {
    // 👇 AGREGA ESTA LÍNEA PARA VER SI LLEGA EL AVISO
    console.log('🔊 ¡BINGO! El celular logró comunicarse. Cuenta:', req.body.cuenta); 
    
    try {
        const { cuenta } = req.body;
        await Auth.findOneAndUpdate(
            { cuenta: cuenta, estado: 'Pendiente' },
            { escaneado: true },
            { sort: { fecha: -1 } }
        );
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Error al notificar escaneo' });
    }
});

// La web pregunta si el QR ya fue escaneado
app.get('/api/auth/check-scan/:cuenta', async (req, res) => {
    try {
        const usuario = await Auth.findOne({ cuenta: req.params.cuenta, estado: 'Pendiente' }).sort({ fecha: -1 });
        res.json({ escaneado: usuario ? usuario.escaneado : false });
    } catch (error) {
        res.status(500).json({ error: 'Error al comprobar estado' });
    }
});
// Generar nuevo QR
app.post('/api/auth', async (req, res) => {
    try {
        const { servicio, cuenta } = req.body;
        
        // Generamos el secreto y la URI del QR automáticamente con speakeasy
        const secret = speakeasy.generateSecret({
            name: `${servicio} (${cuenta})`
        });
        
        const nuevoAuth = new Auth({ 
            servicio, 
            cuenta, 
            secret: secret.base32 // Guardamos la semilla en texto plano (Base32)
        });
        await nuevoAuth.save();
        
        // secret.otpauth_url ya contiene el string exacto que necesita tu Angular para el QR
        res.status(201).json({ uri: secret.otpauth_url, auth: nuevoAuth });
    } catch (error) {
        console.error('Detalle del error en backend:', error); 
        res.status(500).json({ error: 'Error al generar el autenticador' });
    }
});

// Obtener registros
app.get('/api/auth', async (req, res) => {
    try {
        const registros = await Auth.find().sort({ fecha: -1 });
        res.json(registros);
    } catch (error) {
        res.status(500).json({ error: 'Error al obtener registros' });
    }
});

// Revocar
app.patch('/api/auth/:id', async (req, res) => {
    try {
        const actualizado = await Auth.findByIdAndUpdate(
            req.params.id, 
            { estado: 'Revocado' }, 
            { new: true }
        );
        res.json(actualizado);
    } catch (error) {
        res.status(500).json({ error: 'Error al revocar el autenticador' });
    }
});

// Verificar Código TOTP y Cambiar Estado a Activo
app.post('/api/auth/verify', async (req, res) => {
    try {
        const { cuenta, token } = req.body;
        
        // CORRECCIÓN DEL BUG: Buscamos el registro MÁS RECIENTE que esté Pendiente
        const usuario = await Auth.findOne({ cuenta: cuenta, estado: 'Pendiente' }).sort({ fecha: -1 });

        if (!usuario) {
            return res.status(404).json({ success: false, error: 'No hay solicitudes pendientes para esta cuenta' });
        }

        // Verificamos el PIN
        const esValido = speakeasy.totp.verify({
            secret: usuario.secret,
            encoding: 'base32',
            token: token,
            window: 2 // AMPLIAMOS LA TOLERANCIA: Permite 1 minuto de desfase entre PC y celular
        });

        if (esValido) {
            usuario.estado = 'Activo';
            await usuario.save();
            res.json({ success: true, message: '¡Autenticador activado exitosamente!' });
        } else {
            res.status(401).json({ success: false, error: 'Código incorrecto o expirado' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Error al verificar' });
    }
});
module.exports = app;