<?php

namespace App\Repository;

use App\Entity\Artwork;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @extends ServiceEntityRepository<Artwork>
 *
 * @method Artwork|null find($id, $lockMode = null, $lockVersion = null)
 * @method Artwork|null findOneBy(array $criteria, array $orderBy = null)
 * @method Artwork[]    findAll()
 * @method Artwork[]    findBy(array $criteria, array $orderBy = null, $limit = null, $offset = null)
 */
class ArtworkRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, Artwork::class);
    }

    public function add(Artwork $entity, bool $flush = false): void
    {
        $this->getEntityManager()->persist($entity);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }

    public function remove(Artwork $entity, bool $flush = false): void
    {
        $this->getEntityManager()->remove($entity);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }

    /**
     * Fetch artworks by title
     */
    public function getArtworksByTitle(?string $keyword)
    {
        $qb= $this->createQueryBuilder('a')
           ->orderBy('a.id', 'DESC')
           ->where('a.status = TRUE');

            // is there any search ? 
        if ($keyword !== null) {
            // adding a new field to SQL request
            $qb->where('a.title LIKE :keyword')
                ->setParameter('keyword', '%'.$keyword.'%');
        }
           return $qb->getQuery()->getResult()
        ;
    }

}
