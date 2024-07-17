from keri import core
from keri.app import habbing
from keri.core import coring
from kerkle.core.treeing import SparseMerkleTree
from kerkle.core.proofing import verify_proof

CODE=core.MtrDex.Blake3_256


def mess_with_merkle():
    with habbing.openHby(name="verifier", temp=False) as hby:
        tree = SparseMerkleTree(code=CODE)
        for (said,), exn in hby.db.exns.getItemIter():
            saider = coring.Saider(qb64b=exn.saidb)
            tree.update(saider)

        print(len(tree.root_as_bytes()))
        root = core.Matter(raw=tree.root_as_bytes(), code=CODE)
        print(root.qb64)

        said = b"EPmcEGTcF8-xNCOP6Bcg0ar57BVT6TumnJ4quwm-cnTH"
        proof = tree.prove(said)
        print(verify_proof(proof, root.raw, said, said, code=CODE))

        for node in proof.sidenodes:
            mtr = core.Matter(raw=node, code=CODE)
            print(mtr.qb64)


if __name__ == "__main__":
    mess_with_merkle()
