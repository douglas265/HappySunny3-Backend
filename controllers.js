const { sql, poolPromise } = require('./db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// --- Helper function to get CustomerID ---
const getCustomerId = async (pool, userId, companyId) => {
    const result = await pool.request()
        .input('UserID', sql.Int, userId)
        .input('CompanyID', sql.Int, companyId)
        .query('SELECT CustomerID FROM Customers WHERE UserID = @UserID AND CompanyID = @CompanyID');
    return result.recordset.length > 0 ? result.recordset[0].CustomerID : null;
};

// --- User & Auth ---
exports.registerUser = async (req, res) => {
    const { name, email, password, phoneNumber } = req.body;
    if (!name || !email || !password || !phoneNumber) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    const pool = await poolPromise;
    const transaction = pool.transaction();
    try {
        await transaction.begin();
        
        const request = transaction.request();
        const userExistsResult = await request.input('email_check', sql.NVarChar, email).query('SELECT UserID FROM Users WHERE Email = @email_check');
        if (userExistsResult.recordset.length > 0) {
            await transaction.rollback();
            return res.status(409).json({ message: 'User with this email already exists.' });
        }
        
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        const userResult = await request
            .input('fullName', sql.NVarChar, name)
            .input('email', sql.NVarChar, email)
            .input('passwordHash', sql.NVarChar, passwordHash)
            .input('phoneNumber', sql.NVarChar, phoneNumber)
            .query('INSERT INTO Users (FullName, Email, PasswordHash, PhoneNumber) OUTPUT INSERTED.UserID VALUES (@fullName, @email, @passwordHash, @phoneNumber)');
        
        const newUserId = userResult.recordset[0].UserID;
        const defaultCompanyId = 1;

        const customerResult = await request
            .input('UserID_cust', sql.Int, newUserId)
            .input('CompanyID_cust', sql.Int, defaultCompanyId)
            .query('INSERT INTO Customers (UserID, CompanyID) OUTPUT INSERTED.CustomerID VALUES (@UserID_cust, @CompanyID_cust)');
        
        await transaction.commit();
        
        const newCustomerId = customerResult.recordset[0].CustomerID;
        const token = jwt.sign({ 
            id: newUserId, 
            customerId: newCustomerId,
            role: 'customer', 
            companyId: defaultCompanyId 
        }, process.env.JWT_SECRET, { expiresIn: '1d' });

        res.status(201).json({ 
            token, 
            user: { id: newUserId, name, email, role: 'customer', companyId: defaultCompanyId } 
        });

    } catch (err) {
        if (transaction.rolledBack === false) {
           await transaction.rollback();
        }
        console.error('Registration error:', err);
        res.status(500).json({ message: 'Server error during registration.' });
    }
};

exports.loginUser = async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password are required.' });
    
    try {
        const pool = await poolPromise;
        const result = await pool.request()
            .input('email', sql.NVarChar, email)
            .query('SELECT UserID, FullName, Email, PasswordHash FROM Users WHERE Email = @email');
        
        const user = result.recordset[0];
        if (!user) return res.status(401).json({ message: 'Invalid credentials.' });

        const isMatch = await bcrypt.compare(password, user.PasswordHash);
        if (!isMatch) return res.status(401).json({ message: 'Invalid credentials.' });

        const internalUserResult = await pool.request()
            .input('UserID_internal', sql.Int, user.UserID)
            .query('SELECT InternalUserID, CompanyID, UserRole FROM InternalUsers WHERE UserID = @UserID_internal');

        let tokenPayload, userPayload;

        if (internalUserResult.recordset.length > 0) {
            const internalUser = internalUserResult.recordset[0];
            tokenPayload = { id: user.UserID, internalId: internalUser.InternalUserID, role: internalUser.UserRole, companyId: internalUser.CompanyID };
            userPayload = { id: user.UserID, name: user.FullName, email: user.Email, role: internalUser.UserRole, companyId: internalUser.CompanyID, internalId: internalUser.InternalUserID };
        } else {
            const defaultCompanyId = 1;
            const customerId = await getCustomerId(pool, user.UserID, defaultCompanyId);
            
            if (!customerId) return res.status(403).json({ message: 'Customer profile not found for this spa.' });
            
            tokenPayload = { id: user.UserID, customerId: customerId, role: 'customer', companyId: defaultCompanyId };
            userPayload = { id: user.UserID, name: user.FullName, email: user.Email, role: 'customer', companyId: defaultCompanyId };
        }
        
        const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ token, user: userPayload });

    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ message: 'Server error during login.' });
    }
};

exports.getUserProfile = async (req, res) => {
    try {
        const pool = await poolPromise;
        const userResult = await pool.request().input('UserID', sql.Int, req.user.id).query('SELECT UserID, FullName, Email FROM Users WHERE UserID = @UserID');
        const user = userResult.recordset[0];
        if (!user) return res.status(404).json({ message: 'User not found.' });
        
        res.json({ ...user, ...req.user, id: user.UserID, name: user.FullName });
    } catch (err) {
        console.error('Get profile error:', err);
        res.status(500).json({ message: 'Server error.' });
    }
};

exports.forgotPassword = async (req, res) => {
    const { email } = req.body;
    try {
        const pool = await poolPromise;
        const userResult = await pool.request().input('Email', sql.NVarChar, email).query('SELECT UserID FROM Users WHERE Email = @Email');

        if (userResult.recordset.length > 0) {
            const userId = userResult.recordset[0].UserID;
            const resetToken = crypto.randomBytes(20).toString('hex');
            const resetTokenExpires = new Date(Date.now() + 3600000); 

            await pool.request()
                .input('UserID', sql.Int, userId)
                .input('PasswordResetToken', sql.NVarChar, resetToken)
                .input('ResetTokenExpires', sql.DateTime, resetTokenExpires)
                .query('UPDATE Users SET PasswordResetToken = @PasswordResetToken, ResetTokenExpires = @ResetTokenExpires WHERE UserID = @UserID');
            
            // Use environment variable for the frontend URL
            const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
            const resetUrl = `${frontendUrl}/reset-password/${resetToken}`;
            
            console.log('PASSWORD RESET LINK:', resetUrl);
        }
        res.json({ message: 'If a user with that email exists, a password reset link has been sent.' });
    } catch (err) {
        console.error('Forgot password error:', err);
        res.status(500).json({ message: 'Server error.' });
    }
};

exports.resetPassword = async (req, res) => {
    const { token, password } = req.body;
    try {
        const pool = await poolPromise;
        const userResult = await pool.request()
            .input('PasswordResetToken', sql.NVarChar, token)
            .input('CurrentTime', sql.DateTime, new Date())
            .query('SELECT UserID FROM Users WHERE PasswordResetToken = @PasswordResetToken AND ResetTokenExpires > @CurrentTime');
        if (userResult.recordset.length === 0) return res.status(400).json({ message: 'Password reset token is invalid or has expired.' });

        const userId = userResult.recordset[0].UserID;
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        await pool.request()
            .input('UserID', sql.Int, userId)
            .input('PasswordHash', sql.NVarChar, passwordHash)
            .query('UPDATE Users SET PasswordHash = @PasswordHash, PasswordResetToken = NULL, ResetTokenExpires = NULL WHERE UserID = @UserID');
        res.json({ message: 'Password has been reset successfully.' });
    } catch (err) {
        console.error('Reset password error:', err);
        res.status(500).json({ message: 'Server error.' });
    }
};


// --- Company / Store Info ---
exports.getStoreInfo = async (req, res) => {
    try {
        const pool = await poolPromise;
        const result = await pool.request()
            .input('CompanyID', sql.Int, 1)
            .query('SELECT StoreName, Address, OpeningTime, ClosingTime FROM StoreInfo WHERE CompanyID = @CompanyID');
        
        if (result.recordset.length === 0) return res.status(404).json({ message: 'Store information not found.' });

        const storeInfo = result.recordset[0];
        const formatTime = (date) => date ? new Date(date).toTimeString().substring(0, 5) : null;
        
        res.json({ ...storeInfo, OpeningTime: formatTime(storeInfo.OpeningTime), ClosingTime: formatTime(storeInfo.ClosingTime) });
    } catch (err) {
        console.error('Get store info error:', err);
        res.status(500).json({ message: 'Failed to fetch store info.' });
    }
};

// --- Services ---
exports.getAllServices = async (req, res) => {
    try {
        const pool = await poolPromise;
        const result = await pool.request()
            .input('CompanyID', sql.Int, 1)
            .query('SELECT ServiceID as id, ServiceName as name, Description as description, DurationMinutes as duration, Price as price FROM Services WHERE CompanyID = @CompanyID');
        res.json(result.recordset);
    } catch (err) {
        console.error('Get services error:', err);
        res.status(500).json({ message: 'Failed to fetch services.' });
    }
};

exports.createService = async (req, res) => {
    const { name, description, duration, price } = req.body;
    try {
        const pool = await poolPromise;
        const result = await pool.request()
            .input('CompanyID', sql.Int, req.user.companyId)
            .input('ServiceName', sql.NVarChar, name)
            .input('Description', sql.NVarChar, description)
            .input('DurationMinutes', sql.Int, duration)
            .input('Price', sql.Decimal(10, 2), price)
            .query('INSERT INTO Services (CompanyID, ServiceName, Description, DurationMinutes, Price) OUTPUT INSERTED.ServiceID as id, INSERTED.ServiceName as name, INSERTED.Description as description, INSERTED.DurationMinutes as duration, INSERTED.Price as price VALUES (@CompanyID, @ServiceName, @Description, @DurationMinutes, @Price)');
        res.status(201).json(result.recordset[0]);
    } catch (err) {
        console.error('Create service error:', err);
        res.status(500).json({ message: 'Failed to create service.' });
    }
};

exports.updateService = async (req, res) => {
    const { id } = req.params;
    const { name, description, duration, price } = req.body;
    try {
        const pool = await poolPromise;
        const result = await pool.request()
            .input('ServiceID', sql.Int, id)
            .input('ServiceName', sql.NVarChar, name)
            .input('Description', sql.NVarChar, description)
            .input('DurationMinutes', sql.Int, duration)
            .input('Price', sql.Decimal(10, 2), price)
            .input('CompanyID', sql.Int, req.user.companyId)
            .query('UPDATE Services SET ServiceName = @ServiceName, Description = @Description, DurationMinutes = @DurationMinutes, Price = @Price OUTPUT INSERTED.ServiceID as id, INSERTED.ServiceName as name, INSERTED.Description as description, INSERTED.DurationMinutes as duration, INSERTED.Price as price WHERE ServiceID = @ServiceID AND CompanyID = @CompanyID');
        res.json(result.recordset[0]);
    } catch (err) {
        console.error('Update service error:', err);
        res.status(500).json({ message: 'Failed to update service.' });
    }
};

exports.deleteService = async (req, res) => {
    const { id } = req.params;
    try {
        const pool = await poolPromise;
        await pool.request()
            .input('ServiceID', sql.Int, id)
            .input('CompanyID', sql.Int, req.user.companyId)
            .query('DELETE FROM Services WHERE ServiceID = @ServiceID AND CompanyID = @CompanyID');
        res.json({ message: 'Service deleted successfully.' });
    } catch (err) {
        console.error('Delete service error:', err);
        res.status(500).json({ message: 'Failed to delete service.' });
    }
};

// --- Therapists (Employees) ---
exports.getAllTherapists = async (req, res) => {
    const { serviceId } = req.query;
    try {
        const pool = await poolPromise;
        let query;
        const request = pool.request().input('CompanyID', sql.Int, 1);

        if (serviceId) {
            query = `
                SELECT i.InternalUserID as id, u.FullName as name 
                FROM InternalUsers i
                JOIN Users u ON i.UserID = u.UserID
                JOIN EmployeeServices es ON i.InternalUserID = es.InternalUserID
                WHERE i.UserRole = 'employee' AND i.CompanyID = @CompanyID AND es.ServiceID = @ServiceID
            `;
            request.input('ServiceID', sql.Int, serviceId);
        } else {
            query = `
                SELECT i.InternalUserID as id, u.FullName as name 
                FROM InternalUsers i
                JOIN Users u ON i.UserID = u.UserID
                WHERE i.UserRole = 'employee' AND i.CompanyID = @CompanyID
            `;
        }
        const result = await request.query(query);
        res.json(result.recordset);
    } catch (err) {
        console.error('Get therapists error:', err);
        res.status(500).json({ message: 'Failed to fetch therapists.' });
    }
};

// --- Schedules ---
exports.getEmployeeSchedule = async (req, res) => {
    const { employeeId } = req.params; 
    try {
        const pool = await poolPromise;
        const result = await pool.request()
            .input('InternalUserID', sql.Int, employeeId)
            .query('SELECT WorkDate, StartTime, EndTime FROM Schedules WHERE InternalUserID = @InternalUserID');
        
        const formatTime = (date) => date ? new Date(date).toTimeString().substring(0, 5) : null;
        
        const schedule = result.recordset.reduce((acc, curr) => {
            const date = new Date(curr.WorkDate).toISOString().split('T')[0];
            acc[date] = { start: formatTime(curr.StartTime), end: formatTime(curr.EndTime) };
            return acc;
        }, {});
        res.json(schedule);
    } catch (err) {
        console.error('Get schedule error:', err);
        res.status(500).json({ message: 'Failed to fetch schedule.' });
    }
};

exports.updateEmployeeSchedule = async (req, res) => {
    const internalUserId = req.user.internalId;
    const scheduleData = req.body;
    
    if (req.user.role !== 'employee') return res.status(403).json({ message: 'Not authorized.' });
    if (!Array.isArray(scheduleData)) return res.status(400).json({ message: 'Invalid schedule format.' });

    const pool = await poolPromise;
    const transaction = pool.transaction();
    try {
        await transaction.begin();
        for (const day of scheduleData) {
            if (!day.start || !day.end) {
                await new sql.Request(transaction)
                    .input('InternalUserID', sql.Int, internalUserId)
                    .input('WorkDate', sql.Date, day.date)
                    .query('DELETE FROM Schedules WHERE InternalUserID = @InternalUserID AND WorkDate = @WorkDate');
            } else {
                await new sql.Request(transaction)
                    .input('InternalUserID', sql.Int, internalUserId)
                    .input('WorkDate', sql.Date, day.date)
                    .input('StartTime', sql.Time, day.start)
                    .input('EndTime', sql.Time, day.end)
                    .query(`
                        MERGE Schedules AS target
                        USING (SELECT @InternalUserID AS InternalUserID, @WorkDate AS WorkDate) AS source
                        ON (target.InternalUserID = source.InternalUserID AND target.WorkDate = source.WorkDate)
                        WHEN MATCHED THEN
                            UPDATE SET StartTime = @StartTime, EndTime = @EndTime
                        WHEN NOT MATCHED THEN
                            INSERT (InternalUserID, WorkDate, StartTime, EndTime)
                            VALUES (@InternalUserID, @WorkDate, @StartTime, @EndTime);
                    `);
            }
        }
        await transaction.commit();
        res.json({ message: 'Schedule updated successfully.' });
    } catch (err) {
        await transaction.rollback();
        console.error('Update schedule error:', err);
        res.status(500).json({ message: 'Failed to update schedule.' });
    }
};


// --- Reservations ---
const checkConflict = async (pool, internalUserId, dateTime, serviceId, companyId) => {
    const request = pool.request();
    const serviceResult = await request.input('ServiceID_Dur', sql.Int, serviceId).query('SELECT DurationMinutes FROM Services WHERE ServiceID = @ServiceID_Dur');
    if (serviceResult.recordset.length === 0) throw new Error('Service not found.');
    const duration = serviceResult.recordset[0].DurationMinutes;
    const newReservationStart = new Date(dateTime);
    const newReservationEnd = new Date(newReservationStart.getTime() + duration * 60000);

    const conflictCheckResult = await request
        .input('InternalUserID_Conflict', sql.Int, internalUserId)
        .input('CompanyID_Conflict', sql.Int, companyId)
        .input('NewStart', sql.DateTime, newReservationStart)
        .input('NewEnd', sql.DateTime, newReservationEnd)
        .query(`
            SELECT COUNT(r.ReservationID) as conflictCount 
            FROM Reservations r
            JOIN Services s ON r.ServiceID = s.ServiceID
            WHERE r.InternalUserID = @InternalUserID_Conflict 
              AND r.CompanyID = @CompanyID_Conflict
              AND r.Status = 'Confirmed'
              AND (@NewStart < DATEADD(minute, s.DurationMinutes, r.ReservationDateTime) AND @NewEnd > r.ReservationDateTime)
        `);
    return conflictCheckResult.recordset[0].conflictCount > 0;
};

exports.createReservation = async (req, res) => {
    const { serviceId, therapistId, dateTime } = req.body;
    const { companyId, customerId } = req.user;
    
    if (!serviceId || !therapistId || !dateTime) return res.status(400).json({ message: 'Missing required reservation details.' });

    try {
        const pool = await poolPromise;
        if (!customerId) return res.status(404).json({ message: 'Customer profile not found for this company.' });

        const hasConflict = await checkConflict(pool, therapistId, dateTime, serviceId, companyId);
        if (hasConflict) return res.status(409).json({ message: 'This time slot is no longer available. Please select another time.' });
        
        const result = await pool.request()
            .input('CompanyID', sql.Int, companyId)
            .input('CustomerID', sql.Int, customerId)
            .input('InternalUserID', sql.Int, therapistId)
            .input('ServiceID', sql.Int, serviceId)
            .input('ReservationDateTime', sql.DateTime, new Date(dateTime))
            .input('Status', sql.NVarChar, 'Confirmed')
            .query('INSERT INTO Reservations (CompanyID, CustomerID, InternalUserID, ServiceID, ReservationDateTime, Status) OUTPUT INSERTED.* VALUES (@CompanyID, @CustomerID, @InternalUserID, @ServiceID, @ReservationDateTime, @Status)');
        res.status(201).json(result.recordset[0]);
    } catch (err) {
        console.error('Create reservation error:', err);
        res.status(500).json({ message: err.message || 'Failed to create reservation.' });
    }
};
exports.createCustomReservation = async (req, res) => {
    const { serviceId, therapistId, dateTime, customerName, customerPhone } = req.body;
    const { companyId } = req.user;
    if (!serviceId || !therapistId || !dateTime || !customerName || !customerPhone) return res.status(400).json({ message: 'All fields are required.' });

    const pool = await poolPromise;
    const transaction = pool.transaction();
    try {
        await transaction.begin();
        const request = transaction.request();
        
        const hasConflict = await checkConflict(pool, therapistId, dateTime, serviceId, companyId);
        if (hasConflict) {
            await transaction.rollback();
            return res.status(409).json({ message: 'This time slot is already booked.' });
        }

        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(crypto.randomBytes(8).toString('hex'), salt);
        const walkInEmail = `walkin_${Date.now()}@example.com`;

        const userResult = await request
            .input('FullName', sql.NVarChar, customerName)
            .input('Email', sql.NVarChar, walkInEmail)
            .input('PasswordHash', sql.NVarChar, passwordHash)
            .input('PhoneNumber', sql.NVarChar, customerPhone)
            .query('INSERT INTO Users (FullName, Email, PasswordHash, PhoneNumber) OUTPUT INSERTED.UserID VALUES (@FullName, @Email, @PasswordHash, @PhoneNumber)');
        
        const newUserId = userResult.recordset[0].UserID;

        const customerResult = await request
            .input('UserID_cust', sql.Int, newUserId)
            .input('CompanyID_cust', sql.Int, companyId)
            .query('INSERT INTO Customers (UserID, CompanyID) OUTPUT INSERTED.CustomerID VALUES (@UserID_cust, @CompanyID_cust)');
        const customerId = customerResult.recordset[0].CustomerID;

        const reservationResult = await request
            .input('CompanyID_res', sql.Int, companyId)
            .input('CustomerID_res', sql.Int, customerId)
            .input('InternalUserID_res', sql.Int, therapistId)
            .input('ServiceID_res', sql.Int, serviceId)
            .input('ReservationDateTime_res', sql.DateTime, new Date(dateTime))
            .query('INSERT INTO Reservations (CompanyID, CustomerID, InternalUserID, ServiceID, ReservationDateTime, Status) OUTPUT INSERTED.* VALUES (@CompanyID_res, @CustomerID_res, @InternalUserID_res, @ServiceID_res, @ReservationDateTime_res, \'Confirmed\')');
        
        await transaction.commit();
        res.status(201).json(reservationResult.recordset[0]);
    } catch (err) {
        if(transaction.rolledBack === false) await transaction.rollback();
        console.error('Custom reservation error:', err);
        res.status(500).json({ message: 'Failed to create custom reservation.' });
    }
};
exports.getCustomerReservations = async (req, res) => {
    const { customerId, companyId } = req.user;
    try {
        const pool = await poolPromise;
        await pool.request().input('CurrentTime', sql.DateTime, new Date()).query('UPDATE r SET Status = \'Completed\' FROM Reservations r JOIN Services s ON r.ServiceID = s.ServiceID WHERE r.Status = \'Confirmed\' AND DATEADD(minute, s.DurationMinutes, r.ReservationDateTime) < @CurrentTime');
        const result = await pool.request()
            .input('CustomerID', sql.Int, customerId)
            .input('CompanyID', sql.Int, companyId)
            .query(`
                SELECT r.ReservationID, r.ReservationDateTime, r.Status, r.CancellationReason, r.CancelledAt, 
                       s.ServiceName, s.Price, u.FullName AS TherapistName 
                FROM Reservations r 
                JOIN Services s ON r.ServiceID = s.ServiceID 
                JOIN InternalUsers iu ON r.InternalUserID = iu.InternalUserID
                JOIN Users u ON iu.UserID = u.UserID
                WHERE r.CustomerID = @CustomerID AND r.CompanyID = @CompanyID
                ORDER BY r.ReservationDateTime DESC
            `);
        res.json(result.recordset);
    } catch (err) {
        console.error('Get my reservations error:', err);
        res.status(500).json({ message: 'Failed to fetch reservations.' });
    }
};
exports.getEmployeeReservations = async (req, res) => {
    const { internalId, companyId } = req.user;
    const { startDate } = req.query;
    if (!['employee', 'frontdesk', 'admin', 'employer'].includes(req.user.role)) return res.status(403).json({ message: 'Not authorized.' });

    try {
        const pool = await poolPromise;
        const endDate = new Date(startDate);
        endDate.setDate(endDate.getDate() + 7);

        const result = await pool.request()
            .input('InternalUserID', sql.Int, internalId)
            .input('CompanyID', sql.Int, companyId)
            .input('StartDate', sql.Date, startDate)
            .input('EndDate', sql.Date, endDate)
            .query(`
                SELECT r.ReservationID, r.ReservationDateTime, r.Status, r.CancellationReason, r.CancelledAt, 
                       s.ServiceName, s.DurationMinutes, 
                       c_user.FullName AS CustomerName, c_user.PhoneNumber AS CustomerPhone, 
                       e_user.FullName as EmployeeName 
                FROM Reservations r 
                JOIN Services s ON r.ServiceID = s.ServiceID 
                JOIN Customers c ON r.CustomerID = c.CustomerID
                JOIN Users c_user ON c.UserID = c.UserID
                JOIN InternalUsers e ON r.InternalUserID = e.InternalUserID
                JOIN Users e_user ON e.UserID = e_user.UserID
                WHERE r.InternalUserID = @InternalUserID AND r.CompanyID = @CompanyID
                  AND r.ReservationDateTime >= @StartDate AND r.ReservationDateTime < @EndDate 
                ORDER BY r.ReservationDateTime ASC
            `);
        res.json(result.recordset);
    } catch (err) {
        console.error('Get employee reservations error:', err);
        res.status(500).json({ message: 'Failed to fetch employee reservations.' });
    }
};
exports.getTherapistReservationsByDate = async (req, res) => {
    const { therapistId } = req.params;
    const { date } = req.query;
    if (!date) return res.status(400).json({ message: 'Date is required.' });

    try {
        const pool = await poolPromise;
        const result = await pool.request()
            .input('InternalUserID', sql.Int, therapistId)
            .input('ReservationDate', sql.Date, date)
            .query(`
                SELECT r.ReservationDateTime, s.DurationMinutes 
                FROM Reservations r 
                JOIN Services s ON r.ServiceID = s.ServiceID 
                WHERE r.InternalUserID = @InternalUserID 
                  AND CAST(r.ReservationDateTime AS DATE) = @ReservationDate 
                  AND r.Status = 'Confirmed'
            `);
        res.json(result.recordset);
    } catch (err) {
        console.error('Get therapist reservations by date error:', err);
        res.status(500).json({ message: 'Failed to fetch reservations.' });
    }
};
exports.getAllReservations = async (req, res) => {
    const { companyId } = req.user;
    const { startDate, employeeId, status } = req.query;
    if (!startDate) return res.status(400).json({ message: 'Start date is required.' });

    try {
        const pool = await poolPromise;
        await pool.request().input('CurrentTime', sql.DateTime, new Date()).query('UPDATE r SET Status = \'Completed\' FROM Reservations r JOIN Services s ON r.ServiceID = s.ServiceID WHERE r.Status = \'Confirmed\' AND DATEADD(minute, s.DurationMinutes, r.ReservationDateTime) < @CurrentTime');
        
        const endDate = new Date(startDate);
        endDate.setDate(endDate.getDate() + 7);
        let query = `
            SELECT r.ReservationID, r.ReservationDateTime, r.Status, r.CancellationReason, r.CancelledAt, 
                   s.ServiceName, s.DurationMinutes, 
                   c_user.FullName AS CustomerName, c_user.PhoneNumber AS CustomerPhone, 
                   e_user.FullName AS EmployeeName, r.InternalUserID AS EmployeeID 
            FROM Reservations r 
            JOIN Services s ON r.ServiceID = s.ServiceID 
            JOIN Customers c ON r.CustomerID = c.CustomerID
            JOIN Users c_user ON c.UserID = c.UserID
            JOIN InternalUsers e ON r.InternalUserID = e.InternalUserID
            JOIN Users e_user ON e.UserID = e_user.UserID
            WHERE r.CompanyID = @CompanyID 
              AND r.ReservationDateTime >= @StartDate AND r.ReservationDateTime < @EndDate
        `;
        const request = pool.request();
        request.input('CompanyID', sql.Int, companyId);
        request.input('StartDate', sql.Date, startDate);
        request.input('EndDate', sql.Date, endDate);
        if (employeeId && employeeId !== 'all') { query += ' AND r.InternalUserID = @InternalUserID'; request.input('InternalUserID', sql.Int, employeeId); }
        if (status && status !== 'all') { query += ' AND r.Status = @Status'; request.input('Status', sql.NVarChar, status); }
        query += ' ORDER BY r.ReservationDateTime ASC';
        
        const result = await request.query(query);
        res.json(result.recordset);
    } catch (err) {
        console.error('Get all reservations error:', err);
        res.status(500).json({ message: 'Failed to fetch all reservations.' });
    }
};
exports.cancelReservation = async (req, res) => {
    const { role, customerId } = req.user;
    const { id: reservationId } = req.params;
    const { reason } = req.body;
    if (!reason) return res.status(400).json({ message: 'A reason for cancellation is required.' });

    try {
        const pool = await poolPromise;
        const request = pool.request();
        let query;

        if (['employer', 'admin', 'frontdesk'].includes(role)) {
            query = 'UPDATE Reservations SET Status = \'Cancelled\', CancellationReason = @CancellationReason, CancelledAt = @CancelledAt OUTPUT INSERTED.* WHERE ReservationID = @ReservationID';
        } else {
            query = 'UPDATE Reservations SET Status = \'Cancelled\', CancellationReason = @CancellationReason, CancelledAt = @CancelledAt OUTPUT INSERTED.* WHERE ReservationID = @ReservationID AND CustomerID = @CustomerID';
            request.input('CustomerID', sql.Int, customerId);
        }

        request.input('ReservationID', sql.Int, reservationId);
        request.input('CancellationReason', sql.NVarChar, reason);
        request.input('CancelledAt', sql.DateTime, new Date());
        
        const result = await request.query(query);
        if (result.recordset.length === 0) return res.status(404).json({ message: 'Reservation not found or you are not authorized to cancel it.' });
        res.json(result.recordset[0]);
    } catch (err) {
        console.error('Cancel reservation error:', err);
        res.status(500).json({ message: 'Failed to cancel reservation.' });
    }
};

// --- Admin User Management ---
exports.getAllUsers = async (req, res) => {
    try {
        const pool = await poolPromise;
        const result = await pool.request()
            .input('CompanyID', sql.Int, req.user.companyId)
            .query(`
                SELECT 
                    u.UserID as id, 
                    u.FullName, 
                    u.Email, 
                    u.PhoneNumber, 
                    i.InternalUserID,
                    ISNULL(i.UserRole, 'customer') as UserRole
                FROM Users u
                LEFT JOIN InternalUsers i ON u.UserID = i.UserID AND i.CompanyID = @CompanyID
                ORDER BY u.FullName
            `);
        res.json(result.recordset);
    } catch (err) {
        console.error('Get all users error:', err);
        res.status(500).json({ message: 'Failed to fetch users' });
    }
};

exports.createUser = async (req, res) => {
    const { fullName, email, password, phoneNumber, userRole } = req.body;
    const { companyId } = req.user;
    
    const pool = await poolPromise;
    const transaction = pool.transaction();
    try {
        await transaction.begin();
        const request = transaction.request();

        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);
        const userResult = await request
            .input('FullName', sql.NVarChar, fullName)
            .input('Email', sql.NVarChar, email)
            .input('PasswordHash', sql.NVarChar, passwordHash)
            .input('PhoneNumber', sql.NVarChar, phoneNumber)
            .query('INSERT INTO Users (FullName, Email, PasswordHash, PhoneNumber) OUTPUT INSERTED.UserID VALUES (@FullName, @Email, @PasswordHash, @PhoneNumber)');
        
        const newUserId = userResult.recordset[0].UserID;

        if (userRole === 'customer') {
             await request.input('UserID_cust', sql.Int, newUserId).input('CompanyID_cust', sql.Int, companyId).query('INSERT INTO Customers (UserID, CompanyID) VALUES (@UserID_cust, @CompanyID_cust)');
        } else {
            await request.input('UserID_int', sql.Int, newUserId).input('CompanyID_int', sql.Int, companyId).input('UserRole_int', sql.NVarChar, userRole).query('INSERT INTO InternalUsers (UserID, CompanyID, UserRole) VALUES (@UserID_int, @CompanyID_int, @UserRole_int)');
        }
        
        await transaction.commit();
        res.status(201).json({ message: 'User created successfully.' });
    } catch (err) {
        if(transaction.rolledBack === false) await transaction.rollback();
        console.error('Admin create user error:', err);
        if (err.number === 2627) return res.status(409).json({ message: 'User with this email already exists.' });
        res.status(500).json({ message: 'Failed to create user.' });
    }
};
exports.updateUser = async (req, res) => {
    const { id } = req.params; 
    const { fullName, email, phoneNumber, userRole } = req.body;
    const { companyId } = req.user;

    const pool = await poolPromise;
    const transaction = pool.transaction();
    try {
        await transaction.begin();
        const request = transaction.request();
        
        await request
            .input('UserID', sql.Int, id)
            .input('FullName', sql.NVarChar, fullName)
            .input('Email', sql.NVarChar, email)
            .input('PhoneNumber', sql.NVarChar, phoneNumber)
            .query('UPDATE Users SET FullName = @FullName, Email = @Email, PhoneNumber = @PhoneNumber WHERE UserID = @UserID');

        await request.input('UserID_del', sql.Int, id).query('DELETE FROM InternalUsers WHERE UserID = @UserID_del');
        await request.input('UserID_del2', sql.Int, id).query('DELETE FROM Customers WHERE UserID = @UserID_del2');
        
        if (userRole === 'customer') {
            await request.input('UserID_add', sql.Int, id).input('CompanyID_add', sql.Int, companyId).query('INSERT INTO Customers (UserID, CompanyID) VALUES (@UserID_add, @CompanyID_add)');
        } else {
            await request.input('UserID_add2', sql.Int, id).input('CompanyID_add2', sql.Int, companyId).input('UserRole_add', sql.NVarChar, userRole).query('INSERT INTO InternalUsers (UserID, CompanyID, UserRole) VALUES (@UserID_add2, @CompanyID_add2, @UserRole_add)');
        }

        await transaction.commit();
        res.json({ message: 'User updated successfully.' });

    } catch (err) {
        if(transaction.rolledBack === false) await transaction.rollback();
        console.error('Admin update user error:', err);
        res.status(500).json({ message: 'Failed to update user.' });
    }
};
exports.deleteUser = async (req, res) => {
    const { id } = req.params; 
    if (req.user.id == id) return res.status(400).json({ message: "You cannot delete your own account." });

    const pool = await poolPromise;
    try {
        await pool.request()
            .input('UserID', sql.Int, id)
            .query('DELETE FROM Users WHERE UserID = @UserID');
        
        res.json({ message: 'User and all related data deleted successfully.' });
    } catch (err) {
        console.error('Admin delete user error:', err);
        if (err.number === 547) {
            return res.status(409).json({ message: 'Cannot delete user. They may be linked to a company or have existing reservations. Please reassign their records before deleting.' });
        }
        res.status(500).json({ message: 'Failed to delete user.' });
    }
};

// --- Employee Service Assignments ---
exports.getEmployeeServices = async (req, res) => {
    const { internalUserId } = req.params;
    const { role, internalId } = req.user;
    
    if (!['employer', 'admin', 'frontdesk'].includes(role) && internalId != internalUserId) {
        return res.status(403).json({ message: "Not authorized to view this employee's services." });
    }
    
    try {
        const pool = await poolPromise;
        const result = await pool.request()
            .input('InternalUserID', sql.Int, internalUserId)
            .query('SELECT ServiceID FROM EmployeeServices WHERE InternalUserID = @InternalUserID');
        res.json(result.recordset.map(r => r.ServiceID));
    } catch (err) {
        console.error('Get employee services error:', err);
        res.status(500).json({ message: 'Failed to fetch employee services.' });
    }
};

exports.updateEmployeeServices = async (req, res) => {
    const { internalUserId } = req.params;
    const { serviceIds } = req.body;
    const { role, internalId } = req.user;
    
    if (!Array.isArray(serviceIds)) return res.status(400).json({ message: 'serviceIds must be an array.' });
    
    if (!['employer', 'admin', 'frontdesk'].includes(role) && internalId != internalUserId) {
        return res.status(403).json({ message: "Not authorized to update this employee's services." });
    }

    const pool = await poolPromise;
    const transaction = pool.transaction();
    try {
        await transaction.begin();
        const request = transaction.request().input('InternalUserID', sql.Int, internalUserId);

        await request.query('DELETE FROM EmployeeServices WHERE InternalUserID = @InternalUserID');

        if (serviceIds.length > 0) {
            let insertQuery = 'INSERT INTO EmployeeServices (InternalUserID, ServiceID) VALUES ';
            serviceIds.forEach((id, index) => {
                const serviceIdParam = `ServiceID${index}`;
                request.input(serviceIdParam, sql.Int, id);
                insertQuery += `(@InternalUserID, @${serviceIdParam}),`;
            });
            await request.query(insertQuery.slice(0, -1));
        }
        
        await transaction.commit();
        res.json({ message: "Employee's services updated successfully." });

    } catch (err) {
        if(transaction.rolledBack === false) await transaction.rollback();
        console.error('Update employee services error:', err);
        res.status(500).json({ message: 'Failed to update services.' });
    }
};

