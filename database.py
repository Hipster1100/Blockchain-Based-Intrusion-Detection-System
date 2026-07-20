import sqlite3
import json
from datetime import datetime

class Database:
    def __init__(self, db_file='blockchain.db'):
        self.db_file = db_file
        self.conn = None
        self.init_database()
    
    def get_connection(self):
        """Get database connection"""
        if self.conn is None:
            self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
        return self.conn
    
    def init_database(self):
        """Initialize database tables"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Blocks table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                block_index INTEGER UNIQUE NOT NULL,
                timestamp REAL NOT NULL,
                data TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                nonce INTEGER NOT NULL,
                hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Intrusions table (for easier querying)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS intrusions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                block_index INTEGER NOT NULL,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                description TEXT,
                mode TEXT DEFAULT 'DEMO',
                timestamp TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (block_index) REFERENCES blocks (block_index)
            )
        ''')
        
        # System logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                mode TEXT,
                details TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        print("✅ Database initialized successfully")
    
    def save_block(self, block):
        """Save a block to database"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Save block
            cursor.execute('''
                INSERT OR REPLACE INTO blocks 
                (block_index, timestamp, data, previous_hash, nonce, hash)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                block.index,
                block.timestamp,
                json.dumps(block.data),
                block.previous_hash,
                block.nonce,
                block.hash
            ))
            
            # If block contains intrusion data, save to intrusions table
            if isinstance(block.data, dict) and 'type' in block.data:
                cursor.execute('''
                    INSERT INTO intrusions 
                    (block_index, type, severity, source_ip, description, mode, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    block.index,
                    block.data.get('type', 'UNKNOWN'),
                    block.data.get('severity', 'LOW'),
                    block.data.get('src_ip', None),
                    block.data.get('description', ''),
                    block.data.get('mode', 'DEMO'),
                    block.data.get('timestamp', datetime.now().isoformat())
                ))
            
            conn.commit()
            print(f"💾 Block #{block.index} saved to database")
            return True
        except Exception as e:
            print(f"❌ Error saving block: {e}")
            return False
    
    def load_blocks(self):
        """Load all blocks from database"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT block_index, timestamp, data, previous_hash, nonce, hash
                FROM blocks
                ORDER BY block_index ASC
            ''')
            
            blocks_data = cursor.fetchall()
            print(f"📂 Loaded {len(blocks_data)} blocks from database")
            return blocks_data
        except Exception as e:
            print(f"❌ Error loading blocks: {e}")
            return []

    def get_intrusions(self, limit=None, severity=None, mode=None):
        """Get intrusions with optional filters"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            query = "SELECT * FROM intrusions WHERE 1=1"
            params = []

            if severity:
                query += " AND severity = ?"
                params.append(severity)

            if mode:
                query += " AND mode = ?"
                params.append(mode)

            query += " ORDER BY id DESC"

            # Only add LIMIT as a parameter if it's a positive integer
            if limit is not None:
                try:
                    lim = int(limit)
                    if lim > 0:
                        query += " LIMIT ?"
                        params.append(lim)
                except (TypeError, ValueError):
                    pass

            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

        except Exception as e:
            print(f"❌ Error getting intrusions: {e}")
            return []

    def get_statistics(self):
        """Get comprehensive statistics"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Total blocks
            cursor.execute("SELECT COUNT(*) as count FROM blocks")
            total_blocks = cursor.fetchone()['count']
            
            # Total intrusions
            cursor.execute("SELECT COUNT(*) as count FROM intrusions")
            total_intrusions = cursor.fetchone()['count']
            
            # Intrusions by severity
            cursor.execute('''
                SELECT severity, COUNT(*) as count 
                FROM intrusions 
                GROUP BY severity
            ''')
            severity_stats = {row['severity']: row['count'] for row in cursor.fetchall()}
            
            # Intrusions by type
            cursor.execute('''
                SELECT type, COUNT(*) as count 
                FROM intrusions 
                GROUP BY type
            ''')
            type_stats = {row['type']: row['count'] for row in cursor.fetchall()}
            
            # Intrusions by mode
            cursor.execute('''
                SELECT mode, COUNT(*) as count 
                FROM intrusions 
                GROUP BY mode
            ''')
            mode_stats = {row['mode']: row['count'] for row in cursor.fetchall()}
            
            # Top source IPs
            cursor.execute('''
                SELECT source_ip, COUNT(*) as count 
                FROM intrusions 
                WHERE source_ip IS NOT NULL
                GROUP BY source_ip
                ORDER BY count DESC
                LIMIT 10
            ''')
            top_ips = [dict(row) for row in cursor.fetchall()]
            
            return {
                'total_blocks': total_blocks,
                'total_intrusions': total_intrusions,
                'severity_distribution': severity_stats,
                'type_distribution': type_stats,
                'mode_distribution': mode_stats,
                'top_source_ips': top_ips
            }
        except Exception as e:
            print(f"❌ Error getting statistics: {e}")
            return {}
    
    def export_to_json(self):
        """Export entire blockchain to JSON"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM blocks ORDER BY block_index ASC")
            blocks = [dict(row) for row in cursor.fetchall()]
            
            # Parse JSON data field
            for block in blocks:
                block['data'] = json.loads(block['data'])
            
            return blocks
        except Exception as e:
            print(f"❌ Error exporting to JSON: {e}")
            return []
    
    def export_intrusions_csv(self):
        """Export intrusions to CSV format"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT 
                    block_index, type, severity, source_ip, 
                    description, mode, timestamp
                FROM intrusions
                ORDER BY id DESC
            ''')
            
            intrusions = cursor.fetchall()
            
            # Create CSV string
            csv_data = "Block Index,Type,Severity,Source IP,Description,Mode,Timestamp\n"
            for row in intrusions:
                csv_data += f"{row['block_index']},{row['type']},{row['severity']}," \
                            f"{row['source_ip'] or 'N/A'},{row['description']}," \
                            f"{row['mode']},{row['timestamp']}\n"
            
            return csv_data
        except Exception as e:
            print(f"❌ Error exporting to CSV: {e}")
            return ""
    
    def log_system_action(self, action, mode=None, details=None):
        """Log system actions"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO system_logs (action, mode, details)
                VALUES (?, ?, ?)
            ''', (action, mode, details))
            
            conn.commit()
        except Exception as e:
            print(f"❌ Error logging action: {e}")
    
    def clear_database(self):
        """Clear all data (use with caution!)"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM blocks WHERE block_index > 0")
            cursor.execute("DELETE FROM intrusions")
            cursor.execute("DELETE FROM system_logs")
            
            conn.commit()
            print("🗑️ Database cleared (Genesis block preserved)")
            return True
        except Exception as e:
            print(f"❌ Error clearing database: {e}")
            return False
    
    def get_system_logs(self, limit=50):
        """Get recent system logs"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM system_logs 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"❌ Error getting logs: {e}")
            return []
    
    def backup_database(self, backup_file):
        """Create database backup"""
        try:
            import shutil
            shutil.copy2(self.db_file, backup_file)
            print(f"📦 Database backed up to {backup_file}")
            return True
        except Exception as e:
            print(f"❌ Error backing up database: {e}")
            return False
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            self.conn = None
            print("🔒 Database connection closed")
