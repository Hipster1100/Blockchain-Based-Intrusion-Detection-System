import hashlib
import json
import time
from datetime import datetime

class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.calculate_hash()
    
    def calculate_hash(self):
        """Calculate SHA-256 hash of block"""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def mine_block(self, difficulty):
        """Proof of Work - mine block with given difficulty"""
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        print(f"Block mined: {self.hash}")
    
    def to_dict(self):
        """Convert block to dictionary"""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash
        }


class Blockchain:
    def __init__(self, difficulty=2, database=None):
        self.chain = []
        self.difficulty = difficulty
        self.database = database
        self.load_from_database()
        
        # Create genesis block if chain is empty
        if len(self.chain) == 0:
            self.create_genesis_block()
    
    def create_genesis_block(self):
        """Create the first block in the chain"""
        genesis_block = Block(0, time.time(), "Genesis Block", "0")
        genesis_block.mine_block(self.difficulty)
        self.chain.append(genesis_block)
        
        # Save to database
        if self.database:
            self.database.save_block(genesis_block)
            self.database.log_system_action("GENESIS_BLOCK_CREATED", details="Blockchain initialized")
    
    def get_latest_block(self):
        """Get the most recent block"""
        return self.chain[-1]
    
    def add_block(self, data):
        """Add a new block to the chain"""
        previous_block = self.get_latest_block()
        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            data=data,
            previous_hash=previous_block.hash
        )
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)
        
        # Save to database
        if self.database:
            self.database.save_block(new_block)
            if isinstance(data, dict) and 'type' in data:
                self.database.log_system_action(
                    "INTRUSION_DETECTED", 
                    mode=data.get('mode', 'DEMO'),
                    details=f"{data.get('type')} from {data.get('src_ip', 'Unknown')}"
                )
        
        return new_block
    
    def is_chain_valid(self):
        """Validate the entire blockchain"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Check if current block's hash is correct
            if current_block.hash != current_block.calculate_hash():
                print(f"Block {i} has been tampered with!")
                return False
            
            # Check if previous hash matches
            if current_block.previous_hash != previous_block.hash:
                print(f"Block {i} has invalid previous hash!")
                return False
        
        return True
    
    def get_chain(self):
        """Get entire blockchain as list of dictionaries"""
        return [block.to_dict() for block in self.chain]
    
    def get_block_by_index(self, index):
        """Get specific block by index"""
        if 0 <= index < len(self.chain):
            return self.chain[index].to_dict()
        return None
    
    def search_blocks(self, keyword):
        """Search blocks containing keyword in data"""
        results = []
        for block in self.chain:
            if keyword.lower() in json.dumps(block.data).lower():
                results.append(block.to_dict())
        return results
    
    def load_from_database(self):
        """Load blockchain from database"""
        if not self.database:
            return
        
        blocks_data = self.database.load_blocks()
        
        if not blocks_data:
            print("📝 No existing blockchain found in database")
            return
        
        print(f"📂 Loading {len(blocks_data)} blocks from database...")
        
        for block_data in blocks_data:
            # Parse data field
            data = json.loads(block_data['data']) if isinstance(block_data['data'], str) else block_data['data']
            
            # Recreate block
            block = Block(
                index=block_data['block_index'],
                timestamp=block_data['timestamp'],
                data=data,
                previous_hash=block_data['previous_hash']
            )
            block.nonce = block_data['nonce']
            block.hash = block_data['hash']
            
            self.chain.append(block)
        
        print(f"✅ Blockchain loaded: {len(self.chain)} blocks")
        self.database.log_system_action("BLOCKCHAIN_LOADED", details=f"Loaded {len(self.chain)} blocks")